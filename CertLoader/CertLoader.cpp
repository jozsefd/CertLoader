#pragma comment (lib, "Winscard")
#pragma comment (lib, "Crypt32")

#include <Windows.h>

#include <map>
#include <functional>
#include <thread>
#include <iostream>

#include <conio.h>
#include <stdlib.h>

#define MAX_CONTAINER_NAME 256

using namespace std::string_literals;
using namespace std::chrono_literals;

using String = std::string;
using WString = std::wstring;
using octet = uint8_t;
using Blob = std::vector<octet>;

static WString s2ws(const String s) {
	size_t conv_count;
	WString ws;
	ws.resize(s.size() + 1);
	mbstowcs_s(&conv_count, ws.data(), ws.size(), s.c_str(), s.size());
	ws.resize(conv_count - 1);
	return ws;
}

template<typename T>
static T blob_to_hex(const Blob& data) {
	T n;
	auto cnv = [](const octet o) -> T::value_type {
		return o < 10 ? '0' + o : 'A' + o - 10;
	};
	for (auto o: data) {
		n.append(1, cnv(o / 16));
		n.append(1, cnv(o % 16));
	}
	return n;
}

int ReadKey() {
	if (_kbhit()) return _getch();
	return 0;
}

struct Failure {
	using FailureCode = DWORD;
	FailureCode code;
	WString error;
	Failure(WString msg) : error(msg), code(::GetLastError()) {}
	Failure(WString msg, FailureCode code) : error(msg), code(code) {}
};

struct StateChangeEvent {
	enum class Change {
		ReaderAdded,
		ReaderRemoved,
		CardInserted,
		CardRemoved
	};

	StateChangeEvent(const WString& name, Change c)
		: reader{ name }, change{ c }, atr{} {}
	StateChangeEvent(const WString& name, Change c, LPBYTE pb, DWORD cb)
		: reader{ name }, change{ c }, atr{ pb, pb + cb } {}

	virtual WString as_string() {
		static std::map<StateChangeEvent::Change, WString> state_names = {
			{ StateChangeEvent::Change::ReaderAdded, L"Added reader"s },
			{ StateChangeEvent::Change::ReaderRemoved, L"Removed reader"s },
			{ StateChangeEvent::Change::CardInserted, L"Plugged card into"s },
			{ StateChangeEvent::Change::CardRemoved, L"Removed card from"s }
		};
		return state_names[change] + L" " + reader;
	}

	Change change;
	WString reader;
	Blob atr;
};

struct SmartCardContext {
	SCARDCONTEXT handle = 0;

	static SmartCardContext& shared() {
		static thread_local SmartCardContext context;
		return context;
	}

	SmartCardContext() {
		establish();
	}
	virtual ~SmartCardContext() {
		release();
	}

	void establish() {
		HRESULT hr = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &handle);
		if (hr != SCARD_S_SUCCESS) {
			throw Failure{ L"Failed to establish SCard context", (DWORD)hr };
		}
	}
	void release() {
		if ( handle != 0 ) SCardReleaseContext(handle);
		handle = 0;
	}
	void reset() {
		release();
		establish();
	}
};

struct StateVector : public std::vector<SCARD_READERSTATE> {
	std::map<WString, LPCTSTR> names;
	bool add(WString& str) {
		LPCTSTR cpy = _wcsdup(str.c_str());
		auto rc = names.emplace(str, cpy);
		if (rc.second) {
			push_back({ cpy, nullptr, 0, 0, 0, { 0 } });
			return true;
		}
		return false;
	}
	void remove(WString& str) {
		auto r = names.find(str);
		if (r != names.end()) {
			for (auto it = begin(); it != end(); ) {
				if (str == it->szReader) {
					it = erase(it);
				}
				else {
					++it;
				}
			}

			free((LPVOID)r->second);
			names.erase(str);
		}
	}
	std::vector<WString> minus(std::vector<WString> ref) {
		std::vector<WString> ret;
		for (auto& p : names) {
			if (ref.end() == std::find(ref.begin(), ref.end(), p.first)) {
				ret.push_back(p.first);
			}
		}
		return ret;
	}
	virtual ~StateVector() {
		for (auto& s : names) {
			auto sz = s.second;
			if (sz != nullptr) free((LPVOID)sz);
		}
	}
};

struct ReaderStateMonitor {
	StateVector states;

	std::vector<WString> list_readers()
	{
		auto& context = SmartCardContext::shared();
		std::vector<WString> readers;
		DWORD dwLen = SCARD_AUTOALLOCATE;
		LPTSTR mszReaders = nullptr;
		LPTSTR szReader = nullptr;
		HRESULT hr = SCardListReaders(context.handle, NULL, (LPTSTR)&mszReaders, &dwLen);
		bool failed = false;
		switch (hr) {
		case SCARD_S_SUCCESS:
			szReader = mszReaders;
			while (szReader != nullptr && *szReader != 0) {
				readers.emplace_back(szReader);
				szReader += wcslen(szReader) + 1;
			}
			break;
		case SCARD_E_NO_READERS_AVAILABLE:
			break;
		case SCARD_E_SERVICE_STOPPED:
			context.reset();
			break;
		default:
			failed = true;
		}
		if (mszReaders != nullptr) SCardFreeMemory(context.handle, mszReaders);
		if ( failed ) throw Failure{ L"SCardListReaders failed", (DWORD)hr };
		return readers;
	}

	bool peek(std::function<void(StateChangeEvent&)> notify)
	{
		auto& context = SmartCardContext::shared();
		auto readers = list_readers();
		auto removed_readers = states.minus(readers);
		for (auto& reader : removed_readers) {
			auto e = StateChangeEvent(reader, StateChangeEvent::Change::ReaderRemoved);
			notify(e);
			states.remove(reader);
		}
		for (auto& reader : readers) {
			if (states.add(reader)) {
				auto e = StateChangeEvent(reader, StateChangeEvent::Change::ReaderAdded);
				notify(e);
			}
		}
		DWORD count = (DWORD)states.size();
		if (count == 0) {
			return false;
		}

		auto data = states.data();
		HRESULT hr = 0;
		bool fServiceError = false;
		int tryCount = 0;

		do {
			hr = SCardGetStatusChange(context.handle, 0, data, count);
			if (hr != SCARD_S_SUCCESS) {
				// expected issue: happens when the last reader is removed (Win10)
				if (hr == SCARD_E_SERVICE_STOPPED) {
					std::this_thread::sleep_for(500ms);
					context.reset();
					fServiceError = true;
					tryCount++;
					if (tryCount < 2) continue;
					return false;
				}
				return false;
			}
		} while (hr != SCARD_S_SUCCESS);

		for (auto& state : states) {
			DWORD dwEventState = state.dwEventState;
			DWORD dwCurrentState = state.dwCurrentState;
			DWORD dwChanges = (state.dwEventState ^ state.dwCurrentState) & MAXWORD;
			DWORD dwEventNr = state.dwEventState >> 16;

			state.dwCurrentState = state.dwEventState;
			auto name = WString(state.szReader);

			if ((dwChanges & SCARD_STATE_PRESENT & dwEventState) && !(dwEventState & SCARD_STATE_MUTE)) {
				auto e = StateChangeEvent(name, StateChangeEvent::Change::CardInserted, (PBYTE)state.rgbAtr, state.cbAtr);
				notify(e);
			}
			else if ((dwChanges & SCARD_STATE_EMPTY & dwEventState) && dwCurrentState != 0) {
				auto e = StateChangeEvent(name, StateChangeEvent::Change::CardRemoved);
				notify(e);
			}
			else if (fServiceError || (SCARD_STATE_UNAVAILABLE & dwChanges & state.dwEventState)) {
				auto e = StateChangeEvent(name, StateChangeEvent::Change::ReaderRemoved);
				notify(e);
			}
		}

		return false;
	}
};

struct Certificate {
	PCCERT_CONTEXT context = nullptr;
	Certificate(PCCERT_CONTEXT context) : context{ context } {}
	Certificate(const Certificate& cert) : context { cert.context } {
		//FIXME: duplicate context?
	}
	//FIXME: move contructor??

	virtual ~Certificate() {
		if (context != nullptr) CertFreeCertificateContext(context);
	}
	WString subject() const {
		DWORD dwSize = CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
		WString subject;
		subject.resize(dwSize);
		CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (LPWSTR)subject.data(), subject.size());
		return subject;
	}
	WString issuer() const {
		DWORD dwSize = CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
		WString subject;
		subject.resize(dwSize);
		CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, (LPWSTR)subject.data(), subject.size());
		return subject;
	}
	Blob serial() const {
		Blob serial(context->pCertInfo->SerialNumber.pbData, context->pCertInfo->SerialNumber.pbData + context->pCertInfo->SerialNumber.cbData);
		return serial;
	}
};

struct CardKeyContainer {
	HCRYPTPROV handle = 0;

	CardKeyContainer(const WString& reader, const WString& name) {
		WString readerContainer = L"\\\\.\\" + reader + L"\\" + name;

		BOOL fSts = CryptAcquireContext(&handle, readerContainer.c_str(), MS_SCARD_PROV, PROV_RSA_FULL, CRYPT_SILENT);
		if (!fSts) {
			throw Failure{ L"Failed to get key container context!" };
		}
	}
	~CardKeyContainer() {
		if (handle != 0) CryptReleaseContext(handle, 0);
	}
	Certificate get() {
		HCRYPTKEY hKey = 0;
		DWORD dwKeySpec = AT_KEYEXCHANGE;
		DWORD dwError = 0;
		if (!CryptGetUserKey(handle, dwKeySpec, &hKey)) {
			dwError = GetLastError();
			if (dwError == 0x8009000D) {
				dwKeySpec = AT_SIGNATURE;
				if (!CryptGetUserKey(handle, dwKeySpec, &hKey)) {
					dwError = GetLastError();
				}
			}
		}
		if (hKey == 0) {
			throw Failure{ L"Failed to open key container", dwError };
		}

		DWORD dwCertSize = 0;
		PCCERT_CONTEXT pCert = nullptr;
		if (CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &dwCertSize, 0)) {
			Blob certData(dwCertSize, 0x00);
			if (CryptGetKeyParam(hKey, KP_CERTIFICATE, certData.data(), &dwCertSize, 0)) {
				pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certData.data(), dwCertSize);
			} else {
				dwError = GetLastError();
			}
		} else {
			dwError = GetLastError();
		}
		CryptDestroyKey(hKey);
		if (pCert == nullptr) {
			throw Failure{ L"Failed to create certificate context", dwError };
		}

		return Certificate{ pCert };
	}
};

struct CardContainer {
	WString reader;
	HCRYPTPROV handle = 0;

	CardContainer(const WString& reader) : reader{ reader } {
		WString readerContainer = L"\\\\.\\" + reader + L"\\";

		BOOL fSts = CryptAcquireContext(&handle, readerContainer.c_str(), MS_SCARD_PROV, PROV_RSA_FULL, CRYPT_SILENT);
		if (!fSts) {
			throw Failure{ L"Failed to get default context!" };
		}
	}
	~CardContainer() {
		if (handle != 0) CryptReleaseContext(handle, 0);
	}

	void discover(std::function<void(const Certificate&)> callback) {
		CHAR szTemp[MAX_CONTAINER_NAME];
		DWORD dwSize = sizeof(szTemp);
		dwSize = sizeof(szTemp);
		BOOL fSts = CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)szTemp, &dwSize, CRYPT_FIRST);
		if (!fSts) {
			throw Failure{ L"Failed to enumerate key containers!" };
		}

		while (fSts) {
			CardKeyContainer keyContainer{ reader, s2ws(szTemp) };
			callback(keyContainer.get());
			dwSize = sizeof(szTemp);
			fSts = CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)szTemp, &dwSize, CRYPT_NEXT);
		}
	}
};

int main() {
	std::wcout << "Monitoring smart cards, press <ESC> to exit" << std::endl;
	ReaderStateMonitor monitor;
	bool run = true;
	while (run) {
		try {
			monitor.peek([](auto& e) {
				std::wcout << e.as_string() << std::endl;
				switch (e.change) {
				case StateChangeEvent::Change::CardInserted:
					try {
						CardContainer cardContainer{ e.reader };
						std::wcout << L" ATR:" << blob_to_hex<WString>(e.atr) << std::endl;
						cardContainer.discover([](auto& c) {
							std::wcout << L" Certificate" << std::endl
								<< L" - subject: " << c.subject() << std::endl
								<< L" - issuer: " << c.issuer() << std::endl
								<< L" - serial: " << blob_to_hex<WString>(c.serial()) << std::endl;
							});
					}
					catch (const Failure& f) {
						std::wcout << L"Error accessing card container: " << f.error << L" - " << f.code << std::endl;
					}
					break;
				}
				});
		}
		catch (const Failure& f) {
			std::wcout << L"Error getting smart card status: " << f.error << L" - " << f.code << std::endl;
		}

		if (ReadKey() == VK_ESCAPE) {
			run = false;
			break;
		}

		std::this_thread::sleep_for(1s);
	}
	return 0;
}


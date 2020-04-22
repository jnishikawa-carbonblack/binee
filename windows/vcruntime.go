package windows

import (
    "strings"
	"github.com/carbonblack/binee/util"
)

func VcRuntimeHooks(emu *WinEmulator) {
	emu.AddHook("", "_lock", &Hook{
		Parameters: []string{"locknum"},
		Fn:         SkipFunctionCdecl(false, 0x0),
	})
    emu.AddHook("", "_Thrd_hardware_concurrency", &Hook{
        Parameters: []string{},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionCdecl(true, uint64(len(emu.Scheduler.threads)))(emu, in)
		},

    })
	emu.AddHook("", "getenv", &Hook{
        Parameters: []string{"a:varname"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			key := util.ReadASCII(emu.Uc, in.Args[0], 0)
			key = strings.Trim(key, "\x00")
			key = strings.Trim(key, "\u0000")

			var val string
			for _, data := range emu.Opts.Env {
				if data.Key == key {
					val = data.Value
					break
				}
			}

			if val != "" {
				buf := []byte(val)
				emu.Uc.MemWrite(in.Args[1], buf)
				return SkipFunctionStdCall(true, uint64(len(val)))(emu, in)
			}

			// set last error to 0xcb
			emu.setLastError(0xcb)
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},

    })
	emu.AddHook("", "memset", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "memcpy", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "memcmp", &Hook{
        Parameters: []string{"buffer1", "buffer2", "count"},
    })
	emu.AddHook("", "wmemcpy", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "malloc", &Hook{
		Parameters: []string{"size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionCdecl(true, emu.Heap.Malloc(in.Args[0]))(emu, in)
		},
	})
	emu.AddHook("", "free", &Hook{})
	emu.AddHook("", "__telemetry_main_return_trigger", &Hook{})
	emu.AddHook("", "__vcrt_InitializeCriticalSectionEx", &Hook{
		Parameters: []string{"lpCriticalSection", "dwSpinCount", "Flags"},
	})
	emu.AddHook("", "_except_handler4_common", &Hook{Parameters: []string{}})
	emu.AddHook("", "_unlock", &Hook{
		Parameters: []string{"locknum"},
		Fn:         SkipFunctionCdecl(false, 0x0),
	})
}

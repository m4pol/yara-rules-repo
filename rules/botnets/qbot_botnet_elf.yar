rule Qbot_Botnet_ELF {
        meta:
                description = "Use to detect qbot/gafgyt/bashlite botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "13-08-2023"
                update = "28-09-2023"

        strings:
                $s1 = "mainCommSock" nocase
                $s2 = "KHCommSock" nocase
                $s3 = "commServer"
                $s4 = /getRandom*IP/ nocase
                $s5 = "processCmd"
                $s6 = "getOurIP"
                $s7 = "listFork"
                $s8 = "connectTimeout"
                $s9 = "initConnection"
                $s10 = "StartTheLelz" nocase
                $s11 = "makeIPPacket"

                $x1 = "findRandIP"
                $x2 = "makeVSEPacket" nocase
                $x3 = "bot.c"
                $x4 = "flood.c"
                $x5 = "parser.c"
                $x6 = "XMAS"
                $x7 = "STOMP"
                $x8 = "STOP"
                $x9 = "ack_flood"
                $x10 = "syn_flood"
                $x11 = "vse_flood"
                $x12 = "[43mINFECTED" nocase
                $x13 = "Invalid flag \"%s\""
                $x14 = { 5B 31 3B 33 ?? 6D ?? ?? }
                $x15 = { 73 65 6E 64 ?? 76 68 ?? 79 70 61 73 73 ?? ?? }
                $x16 = { 4F 56 48 ?? ?? ?? }

                $bc1 = { 7d ff ff eb } //killer function call
                $bc2 = { e1 ff ff eb } //kill_main function call
                $bc3 = { d4 02 00 eb } //parser function call
                $bc4 = { c7 44 ?4 28 d4 6f 05 08 } //suspect hex value initialize 1
                $bc5 = { c7 44 ?4 20 e0 70 05 08 } //suspect hex value initialize 2
                $bc6 = { c7 44 ?4 28 e0 71 05 08 } //suspect hex value initialize 3
                $bc7 = { c7 44 ?4 28 d4 6f 05 08 } //suspect hex value initialize 4

        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        (($s1 or $s2) and $s5 and $s9) and
                        (3 of ($s3, $s4, $s6, $s7, $s8, $s10, $s11) or any of ($bc*)) or any of ($x*)
                )
}
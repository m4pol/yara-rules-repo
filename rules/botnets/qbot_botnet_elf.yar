rule Qbot_Botnet_ELF {
        meta:
                description = "Use to detect qbot/gafgyt/bashlite botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "13-08-2023"
                update = "21-02-2024"

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

                $variant1 = "findRandIP"
                $variant2 = "makeVSEPacket" nocase
                $variant3 = "bot.c"
                $variant4 = "flood.c"
                $variant5 = "parser.c"
                $variant6 = "XMAS"
                $variant7 = "STOMP"
                $variant8 = "STOP"
                $variant9 = "ack_flood"
                $variant10 = "syn_flood"
                $variant11 = "vse_flood"
                $variant12 = "[43mINFECTED" nocase
                $variant13 = "Invalid flag \"%s\""
                $variant14 = { 5B 31 3B 33 ?? 6D ?? ?? }
                $variant15 = { 73 65 6E 64 ?? 76 68 ?? 79 70 61 73 73 ?? ?? }
                $variant16 = { 4F 56 48 ?? ?? ?? }

                $bytecode1 = { 7d ff ff eb } //killer function call
                $bytecode2 = { e1 ff ff eb } //kill_main function call
                $bytecode3 = { d4 02 00 eb } //parser function call
                $bytecode4 = { c7 44 ?4 28 d4 6f 05 08 } //suspect hex value initialize 1
                $bytecode5 = { c7 44 ?4 20 e0 70 05 08 } //suspect hex value initialize 2
                $bytecode6 = { c7 44 ?4 28 e0 71 05 08 } //suspect hex value initialize 3
                $bytecode7 = { c7 44 ?4 28 d4 6f 05 08 } //suspect hex value initialize 4

        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        (($s1 or $s2) and $s5 and $s9) and
                        (3 of ($s3, $s4, $s6, $s7, $s8, $s10, $s11) or any of ($bytecode*)) or any of ($variant*)
                )
}
rule Qbot_Botnet_ELF {
        meta:
                description = "Use to detect qbot/gafgyt/bashlite botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "13-08-2023"
                update = "28-02-2024"

        strings:
                $s1 = { ( 4b 48 | 6d 61 69 6e ) ( 43 | 63 ) 6f 6d 6d 53 ( 6f 63 6b | 4F 43 4B ) } //C2 server varible initializing.
                $s2 = "commServer"
                $s3 = /getRandom*IP/ nocase
                $s4 = "processCmd"
                $s5 = "getOurIP"
                $s6 = "listFork"
                $s7 = "connectTimeout"
                $s8 = "initConnection"
                $s9 = "StartTheLelz" nocase
                $s10 = "makeIPPacket"

                $variant1 = "findRandIP"
                $variant2 = "makeVSEPacket" nocase
                $variant3 = "bot.c"
                $variant4 = "flood.c"
                $variant5 = "parser.c"
                $variant6 = "killer.c"
                $variant7 = "XMAS"
                $variant8 = "STOMP"
                $variant9 = "STOP"
                $variant10 = "ack_flood"
                $variant11 = "syn_flood"
                $variant12 = "vse_flood"
                $variant13 = "[43mINFECTED" nocase
                $variant14 = "Invalid flag \"%s\""
                $variant15 = { 73 65 6E 64 ?? 76 68 ?? 79 70 61 73 73 ?? ?? }
                $variant16 = { 4F 56 48 ?? ?? ?? }
                $variant17 = { 5B 31 3B 33 ?? 6D ?? ?? }

                $bytecode1 = { e8 e1 f8 ff ff } //killer function call.
                $bytecode2 = { ( e8 02 fe ff ff | ( 1c f9 | 13 fe ) ff eb ) } //initConnection function call.
                $bytecode3 = { ( e8 c3 e2 ff ff | ( 6b f9 | c4 f5 ) ff eb ) } //processCmd function call
                $bytecode4 = { ( e8 57 e5 ff ff | 14 fb ff eb ) } //sendUDP function call.
                $bytecode5 = { 4? c7 45 ?? c0 ca 40 00 } //STDHEX payload varible initializing.

        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        (($s1 or $s2) and $s5 and $s9) and
                        (3 of ($s3, $s4, $s6, $s7, $s8, $s10) or any of ($bytecode*)) or any of ($variant*)
                )
}
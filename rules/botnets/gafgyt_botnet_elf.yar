rule Gafgyt_Botnet_ELF {
        meta:
                description = "Use to detect Gafgyt botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "15-03-2024"

        strings:
                $s1 = /(KH|main)CommSock/
                $s2 = /(comm|current)Server/
                $s3 = "makeIPPacket"
                $s4 = "initConnection"
                $s5 = "processCmd"
                $s6 = "getRandomIP"
                $s7 = "listFork"
                $s8 = "getOurIP"

                /*
                        Pattern of initConnection function call.
                */
                $hex1 = { e8 [2] ff ff 85 c0 74 0? ( bf 05 00 00 00 e8 | c7 04 ?? 05 00 00 00 e8 | 83 ec 0c 6a 05 e8 ) }
                $hex2 = { eb 00 30 a0 e1 00 00 53 e3 [3] 0a 05 00 a0 e3 [3] eb } //ARM
                
                /*
                        Pattern of processCmd function call.
                */
                $hex3 = { ( 4? 8d ?? ?0 ff ff ff 8b 7? ?? e8 | 8d ?? 90 89 44 ?? ?? 8b 4? ?? 89 04 ?? e8 ) }
                $hex4 = { 78 30 4b e2 ?? 0? 1? e5 03 10 a0 e1 [3] eb } //ARM

        condition:
                uint32(0) == 0x464C457F and filesize > 50KB and filesize <= 180KB and (
                        (($s1 and $s2 and $s3) or (($s4 or ($hex1 or $hex2)) or ($s5 or ($hex3 or $hex4)))) and (2 of ($s6, $s7, $s8))
                )
}
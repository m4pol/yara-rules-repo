rule Mirai_Botnet_ELF {
        meta:
                description = "Use to detect Mirai botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "15-03-2024"

        strings:
                $s1 = ".mdebug.abi32"
                $s2 = "M-SEARCH * HTTP/1.1"
                $s3 = "nickname"
                $s4 = "dvrHelper"
                $s5 = /\/*\/condi/

                /*
                        Pattern of argument passing to the loader function.
                */
                $hex1 = { e8 [4] 59 5e 6a 00 68 [4] e8 [4] 58 5a 6a 00 68 [4] e8 }

                /*
                        Pattern of GET Request header binding.
                */
                $hex2 = { 00 20 a0 e1 [2] 9f e5 00 50 a0 e1 04 00 a0 e1 [3] eb } //ARM

                /*
                        Pattern of XOR GET Request header binding.
                */
                $hex3 = { b? [4] 31 c0 4? 54 55 53 4? 89 fb 4? 81 ec e8 00 00 00 4? 8d ?? ?4 80 00 00 00 4? 89 ef e8 }

                /*
                        Pattern of Web server binding.
                */
                $hex4 = { 68 [4] 68 [4] 8d ?? ?4 a7 07 00 00 53 e8 }
                $hex5 = { 3? 9? e5 [2] 9f e5 [2] 9f e5 05 00 a0 e1 [3] eb } //ARM

                /*
                        Pattern of busybox usage to argument passing.
                */
                $hex6 = { 9f e5 2c 00 80 e2 0e 30 a0 e3 [3] eb } //ARM

        condition:
                uint32(0) == 0x464C457F and filesize <= 200KB and (any of ($s*) and any of ($hex*))
}
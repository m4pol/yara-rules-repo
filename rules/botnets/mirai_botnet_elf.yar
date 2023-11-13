rule Mirai_Botnet_ELF_Packed {
        meta:
                description = "Use to detect packed mirai, and there variants."
                author = "Phatcharadol Thangplub"
                date = "14-08-2023"

        strings:
                $s1 = "SNQUERY"
                $s2 = "RVSPUWVS"
                $s3 = { ?? ?? ?? 76 72 40 4d 2d 53 45 41 52 43 48 20 2a 20 48 54 54 50 da 9b e1 cd ?? ?? }
                $s4 = { ?? 58 50 3b }
                $s5 = { ba 85 09 54 65 61 6d 53 70 08 ?? }

                $x1 = "$Info: This file is packed with the UPX executable packer" nocase
                $x2 = "UPX!" nocase
                $x3 = { ?? 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 ?? } 

        condition:
               uint32(0) == 0x464C457F and filesize < 200KB and 2 of ($s*) and 2 of ($x*)
}

rule Mirai_Botnet_ELF_Unpacked {
        meta:
                description = "Use to detect unpacked mirai, and there variants."
                author = "Phatcharadol Thangplub"
                date = "13-08-2023"
                update = "28-09-2023"

        strings:
                $s1 = ".mdebug.abi32" nocase
                $s2 = "TSource Engine Query" nocase
                $s3 = "M-SEARCH * HTTP/1.1"
                $s4 = "nickname"
                $s5 = "Windows XP"
                $s6 = { ?? 54 65 61 6d 53 70 65 61 6b }
                $s7 = { ?? ?? ?? ?? 3a 20 ?? ?? ?? 2e 32 35 35 2e 32 35 35 2e ?? ?? ?? 3a 31 39 30 30 }
                $s8 = { 51 51 6a ?? 50 }

                $x1 = "\"3DUfw"
                $x2 = "FLOODING TCP"
                $x3 = "FLOODING GTCP"
                $x4 = "FLOODING GRE"
                $x5 = "CNC connection timed out!"
                $x6 = "connection initialized to cnc!"
                $x7 = "boat: applet not found"
                $x8 = "%*d %*s %*c %d" nocase
                $x9 = "condi2 %s:%d" nocase
                $x10 = "/tmp/updateproc" nocase
                $x11 = /\/*\/condi/ nocase
                $x12 = "attack.c"
                $x13 = "attack_tcp.c"
                $x14 = "attack_udp.c"
                $x15 = "killer.c"
                $x16 = { 2F 62 69 6E 2F 63 ?? 6E 64 69 }
                $x17 = { 5B 62 6F 74 70 6B 74 5D 20 ?? ?? ?? ?? }
                $x18 = { 5B 45 52 52 4F 52 5D 20 ?? ?? ?? ?? }
                $x19 = { 5B 6B 69 6C 6C 65 72 5D ?? ?? ?? ?? }
                $x20 = { 50 4D 4D 56 ?? }
                $x21 = { 73 75 63 6b 6d 61 64 69 63 6b }
                $x22 = { 49 57 69 6c 6c 4e 75 6c 6c 59 6f 75 72 54 6f 61 73 74 65 72 }
                
                /*
                        XOR argument passing to the possible loader function.

                        00401be4 31 f6           XOR        param_2,param_2
                        00401be6 bf 22 40        MOV        param_1,s_cundi.arm_00414022
                                 41 00
                        00401beb 4c 8d b4        LEA        R14=>local_30,[RSP + 0x418]
                                 24 18 04 
                                 00 00
                        00401bf3 e8 48 1a        CALL       FUN_00403640
                                 00 00

                        00401c1c 31 f6           XOR        param_2,param_2
                        00401c1e bf 4d 40        MOV        param_1,s_cundi.mips_0041404d
                                 41 00
                        00401c23 e8 18 1a        CALL       FUN_00403640
                                 00 00

                        00401c34 31 f6           XOR        param_2,param_2
                        00401c36 bf 63 40        MOV        param_1,s_cundi.x86_64_00414063
                                 41 00
                        00401c3b e8 00 1a        CALL       FUN_00403640
                                 00 00
                */
                $bc1 = { 31 f6 bf ?? ?? ?? ?? 4? 8d b4 ?4 18 04 00 00 e8 48 1a 00 00 }
                $bc2 = { 31 f6 bf ?? ?? ?? ?? e8 ?? 1a 00 00 }

                /*
                        Another XOR argument passing to the possible loader function.

                        004063d0 31 f6           XOR        param_2, param_2
                        004063d2 bf b0 0a        MOV        param_1=>s_mipsel_00410ab0, s_mipsel_00410ab0
                        004063d7 e8 54 3b        CALL       FUN_00409f30

                        004063dc 31 f6           XOR        param_2, param_2
                        004063de bf b7 0a        MOV        param_1=>s_x86_64_00410ab7, s_x86_64_00410ab7
                        004063e3 e8 48 3b        CALL       FUN_00409f30
                */
                $bc3 = { 31 f6 bf ?? ?? ?? ?? e8 ?? 3b 00 00 }
                
                $bc4 = { 4? 89 fa be 98 16 41 00 } //HTTP Header initialize, from the possible loader function.
                $bc5 = { 66 c7 84 ?4 ?? 07 00 00 02 00 c7 04 ?4 ?? ?? ?? ?? } //Suspect IP Address argument passing.
                $bc6 = { 66 89 8c ?4 ?? 07 00 00 c7 04 ?4 ?? ?? ?? ?? } //Another Suspect IP Address argument passing.
                
        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        ($s3 and $s4 and $s5 and $s6 and $s7) or
                        ((1 of ($s1, $s2) and $s8) or any of ($bc*)) or any of ($x*)
                )
}
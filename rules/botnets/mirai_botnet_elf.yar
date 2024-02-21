import "elf"

rule Mirai_Botnet_ELF_Packed {
        meta:
                description = "Use to detect packed mirai, and there variants."
                author = "Phatcharadol Thangplub"
                date = "14-08-2023"
                update = "21-02-2024"
                ssdp_attack_reference = "https://www.netscout.com/sites/default/files/asert-blog/uploads/2018/06/ssdp_diffraction.pdf"

        strings:
                $s1 = "SNQUERY" //Unique string.
                $s2 = "RVSPUWVS" //Unique string.
                $s3 = { ?? ?? ?? 76 72 40 4d 2d 53 45 41 52 43 48 20 2a 20 48 54 54 50 da 9b e1 cd ?? ?? } //UPNP Header.
                $s4 = { ?? 58 50 3b } //Windows XP artifact.
                $s5 = { ba 85 09 54 65 61 6d 53 70 08 ?? } //TeamSpeak artifact.

                $upx1 = "$Info: This file is packed with the UPX executable packer" nocase
                $upx2 = "UPX!" nocase
                $upx3 = "/proc/self/exe" nocase //UPX packer artifact.

        condition:
               uint32(0) == 0x464C457F and filesize < 200KB and 2 of ($s*) and 2 of ($upx*)
}

rule Mirai_Botnet_ELF_Unpacked {
        meta:
                description = "Use to detect unpacked mirai, and there variants."
                author = "Phatcharadol Thangplub"
                date = "13-08-2023"
                update = "21-02-2024"
                ssdp_attack_reference = "https://www.netscout.com/sites/default/files/asert-blog/uploads/2018/06/ssdp_diffraction.pdf"

        strings:
                $s1 = ".mdebug.abi32" nocase
                $s2 = "TSource Engine Query" nocase
                $s3 = "M-SEARCH * HTTP/1.1"
                $s4 = "nickname"
                $s5 = "Windows XP"
                $s6 = { ?? 54 65 61 6d 53 70 65 61 6b } //Part of TeamSpeak.
                $s7 = { ?? ?? ?? ?? 3a 20 ?? ?? ?? 2e 32 35 35 2e 32 35 35 2e ?? ?? ?? 3a 31 39 30 30 } //UPNP Host Address.
                $s8 = { 51 51 6a ?? 50 } //Unique string.

                $variant1 = "\"3DUfw"
                $variant2 = "FLOODING TCP"
                $variant3 = "FLOODING GTCP"
                $variant4 = "FLOODING GRE"
                $variant5 = "CNC connection timed out!"
                $variant6 = "connection initialized to cnc!"
                $variant7 = "boat: applet not found"
                $variant8 = "%*d %*s %*c %d" nocase
                $variant9 = "condi2 %s:%d" nocase
                $variant10 = "/tmp/updateproc" nocase
                $variant11 = /\/*\/condi/ nocase
                $variant12 = "attack.c"
                $variant13 = "attack_tcp.c"
                $variant14 = "attack_udp.c"
                $variant15 = "killer.c"
                $variant16 = { 2F 62 69 6E 2F 63 ?? 6E 64 69 } //Condi botnet path.
                $variant17 = { 5B 62 6F 74 70 6B 74 5D 20 ?? ?? ?? ?? } //Server Command Report 1.
                $variant18 = { 5B 45 52 52 4F 52 5D 20 ?? ?? ?? ?? } //Server Command Report 2.
                $variant19 = { 5B 6B 69 6C 6C 65 72 5D ?? ?? ?? ?? } //Server Command Report 3.
                $variant20 = { 50 4D 4D 56 ?? } //Unique string.
                
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
                $bytecode1 = { 31 f6 bf ?? ?? ?? ?? 4? 8d b4 ?4 18 04 00 00 e8 48 1a 00 00 }
                $bytecode2 = { 31 f6 bf ?? ?? ?? ?? e8 ?? 1a 00 00 }

                /*
                        Another XOR argument passing to the possible loader function.

                        004063d0 31 f6           XOR        param_2, param_2
                        004063d2 bf b0 0a        MOV        param_1=>s_mipsel_00410ab0, s_mipsel_00410ab0
                        004063d7 e8 54 3b        CALL       FUN_00409f30

                        004063dc 31 f6           XOR        param_2, param_2
                        004063de bf b7 0a        MOV        param_1=>s_x86_64_00410ab7, s_x86_64_00410ab7
                        004063e3 e8 48 3b        CALL       FUN_00409f30
                */
                $bytecode3 = { 31 f6 bf ?? ?? ?? ?? e8 ?? 3b 00 00 }
                
                $bytecode4 = { 4? 89 fa be 98 16 41 00 } //HTTP Header initialize, from the possible loader function.
                $bytecode5 = { 66 c7 84 ?4 ?? 07 00 00 02 00 c7 04 ?4 ?? ?? ?? ?? } //Suspect IP Address argument passing.
                $bytecode6 = { 66 89 8c ?4 ?? 07 00 00 c7 04 ?4 ?? ?? ?? ?? } //Another Suspect IP Address argument passing.
                
        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        ($s3 and $s4 and $s5 and $s6 and $s7) or
                        ((1 of ($s1, $s2) and $s8) or any of ($bytecode*)) or any of ($variant*)
                )
}
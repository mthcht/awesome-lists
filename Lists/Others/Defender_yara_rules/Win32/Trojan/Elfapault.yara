rule Trojan_Win32_Elfapault_A_2147598567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elfapault.A"
        threat_id = "2147598567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elfapault"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 00 8d 4c 24 14 51 6a 40 8d 54 24 38 52 56 ff d7 66 81 7c 24 2c 4d 5a 75}  //weight: 2, accuracy: High
        $x_2_2 = {8d 55 14 8b 0a 3b ce 73 02 8b f1 83 c2 28 48 75 f2 8b 7c 24 2c 8b 4c 24 18 6a 00}  //weight: 2, accuracy: High
        $x_2_3 = {33 c9 66 8b 0a 8b c1 25 ff 0f 00 00 03 06 81 e1 00 f0 00 00 03 c7 81 f9 00 30 00 00 75 02 01 28 83 c2 02 4b}  //weight: 2, accuracy: High
        $x_1_4 = {6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63}  //weight: 1, accuracy: High
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Elfapault_B_2147599340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elfapault.B"
        threat_id = "2147599340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elfapault"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net stop sharedaccess" ascii //weight: 1
        $x_1_2 = "int ut suc!" ascii //weight: 1
        $x_1_3 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6c 73 61 73 73 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Sending payload2...finish" ascii //weight: 1
        $x_1_5 = "4b324fc8-1670-01d3-1278-5a47bf6ee188" ascii //weight: 1
        $x_1_6 = "f:\\source\\cg\\cgall\\ide_hackdriver\\objfre_wxp_x86\\i386\\pcidisk.pdb" ascii //weight: 1
        $x_1_7 = {68 74 74 70 3a 2f 2f [0-48] 2f 65 6c 66 5f 6c 69 73 74 6f 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_8 = "CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_9 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_10 = "\"Mi\"+\"crosoft.XM\"+\"LHTTP\"" ascii //weight: 1
        $x_1_11 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 63 74 66 6d 6f 6e ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_12 = "f:\\windows\\system32\\com\\comrecfg.exe" ascii //weight: 1
        $x_1_13 = "read_pe_info successed" ascii //weight: 1
        $x_1_14 = "sorryiloveyou" ascii //weight: 1
        $x_1_15 = "received exit signal, exited.." ascii //weight: 1
        $x_4_16 = {8b d0 c1 fa 03 8a 14 32 8a c8 80 e1 07 d2 fa 80 e2 01 88 90 c0 76 41 00 40 83 f8 40 7c e2 33 c0 0f be 88 60 6f 40 00 8a 91 bf 76 41 00 0f be 88 61 6f 40 00 88 90 18 6f 41 00 8a 91 bf 76 41 00 0f be 88 62 6f 40 00 88 90 19 6f 41 00 8a 91 bf 76 41 00 0f be 88 63 6f 40 00 88 90 1a 6f 41 00 8a 91 bf 76 41 00 88 90 1b 6f 41 00 83 c0 04 83 f8 40 7c ac 8a 44 24 24 84 c0 8b 5c 24 20 ba 10 00 00 00 8b ca be 18 6f 41 00 bf c0 76 41 00 f3 a5 0f 85 91 00 00 00 a1}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


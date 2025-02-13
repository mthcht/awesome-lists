rule Ransom_Win32_Wadhrama_A_2147720056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wadhrama.A!rsm"
        threat_id = "2147720056"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadhrama"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ":\\crysis\\Release\\PDB\\payload.pdb" ascii //weight: 3
        $x_1_2 = {44 00 65 00 6e 00 69 00 65 00 64 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 54 00 49 00 4f 00 4e 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = ";.mxl;.myd;.myi;.nef;.nrw;.obj;." wide //weight: 1
        $x_1_4 = "con cp select=1251" ascii //weight: 1
        $x_1_5 = "delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Wadhrama_A_2147723889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wadhrama.A!!Wadhrama.gen!A"
        threat_id = "2147723889"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadhrama"
        severity = "Critical"
        info = "Wadhrama: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ":\\crysis\\Release\\PDB\\payload.pdb" ascii //weight: 3
        $x_3_2 = {63 6f 6e 20 63 70 20 73 65 6c 65 63 74 3d 31 32 35 31 0a 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74}  //weight: 3, accuracy: High
        $x_1_3 = {8b 4d f4 33 44 0d c8 8b 55 f4 89 44 15 c8 8b 45 f4 83 c0 04 89 45 f4 83 7d f4 20}  //weight: 1, accuracy: High
        $x_1_4 = {44 00 65 00 6e 00 69 00 65 00 64 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 54 00 49 00 4f 00 4e 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = ";.mxl;.myd;.myi;.nef;.nrw;.obj;." wide //weight: 1
        $x_1_6 = "con cp select=1251" ascii //weight: 1
        $x_1_7 = "delete shadows /all /quiet" ascii //weight: 1
        $n_50_8 = "out\\Release\\360EntClient.pdb" ascii //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Wadhrama_B_2147726308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wadhrama.B"
        threat_id = "2147726308"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadhrama"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "aaa_TouchMeNot_.txt" ascii //weight: 10
        $x_2_2 = "@WannaDecryptor@" wide //weight: 2
        $x_2_3 = "readmewb.txt" wide //weight: 2
        $x_2_4 = "desktopWC.JPG" wide //weight: 2
        $x_2_5 = ".[twist@airmail.cc].twist" wide //weight: 2
        $x_2_6 = "If you want restore your files write on email - twist@airmail.cc" ascii //weight: 2
        $x_2_7 = "How_Decrypt_Files.txt" wide //weight: 2
        $x_2_8 = "READ ME FOR DECRYPT.txt" wide //weight: 2
        $x_2_9 = "BlackStarMafia@qq.com" ascii //weight: 2
        $x_2_10 = "All your files is encrypted using an unknown algorithm!" ascii //weight: 2
        $x_2_11 = ".[aidaclark2@aol.com].arrow" wide //weight: 2
        $x_2_12 = "C:\\crysis\\Release\\PDB\\payload.pdb" ascii //weight: 2
        $x_2_13 = ".[zahra_bloom@aol.com].arrow" wide //weight: 2
        $x_2_14 = ".[bitcoin888@cock.li].arrow" wide //weight: 2
        $x_2_15 = ".[elementtrumpa@tutanota.com].arrow" wide //weight: 2
        $x_2_16 = "D:\\#_src\\projects\\RansomwareTest\\Debug\\RansomwareTest.pdb" ascii //weight: 2
        $x_2_17 = "%d files was encrypted. press any key" wide //weight: 2
        $x_2_18 = "_HELP_INSTRUCTIONS_.TXT" wide //weight: 2
        $x_2_19 = "B040A3ED27C166CBC4E8D0E1286347F3.MOLE66" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Wadhrama_ME_2147916400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wadhrama.ME!MTB"
        threat_id = "2147916400"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadhrama"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 0f af 45 ?? 03 c6 8b 4d ?? 8d 04 c1 89 45 ?? 8a 45 ?? 32 c3 88 45 ?? 66 83 7d ?? 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


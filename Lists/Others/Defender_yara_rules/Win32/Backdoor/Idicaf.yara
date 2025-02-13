rule Backdoor_Win32_Idicaf_A_2147627569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Idicaf.gen!A"
        threat_id = "2147627569"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Idicaf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $n_100_1 = "\\Simply Super Software\\Trojan Remover\\" ascii //weight: -100
        $x_20_2 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 20, accuracy: High
        $x_1_3 = "Inject" ascii //weight: 1
        $x_1_4 = "KeyLog" ascii //weight: 1
        $x_1_5 = "shutdown" ascii //weight: 1
        $x_1_6 = "logonui.exe" ascii //weight: 1
        $x_1_7 = "rundll64.exe" ascii //weight: 1
        $x_1_8 = "delhostinfo" ascii //weight: 1
        $x_1_9 = "%s\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_10 = "del \"%s" ascii //weight: 1
        $x_1_11 = "\\vmselfdel.bat" ascii //weight: 1
        $x_1_12 = "attrib -a -r -s -h \"%s" ascii //weight: 1
        $x_1_13 = "if exist \"%s\" goto selfkill" ascii //weight: 1
        $x_1_14 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Idicaf_B_2147647668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Idicaf.gen!B"
        threat_id = "2147647668"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Idicaf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 0c 6a ?? 5f 8d 0c 06 8b c6 99 f7 ff b0 ?? 2a c2 00 01 46}  //weight: 2, accuracy: Low
        $x_1_2 = "plug_keylog" ascii //weight: 1
        $x_1_3 = {5b 53 53 44 54 [0-1] 52 69 6e 67 30 [0-4] 3a 5d 20 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


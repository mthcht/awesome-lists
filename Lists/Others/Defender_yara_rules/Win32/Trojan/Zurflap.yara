rule Trojan_Win32_Zurflap_B_2147749091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zurflap.B!dha"
        threat_id = "2147749091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zurflap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RunRunEvent" ascii //weight: 2
        $x_2_2 = "DelDelMutex" ascii //weight: 2
        $x_2_3 = ".?AVCMemLoadDll@@" ascii //weight: 2
        $x_2_4 = "IFirstDll.dll" ascii //weight: 2
        $x_2_5 = {9f 2e fe 6e 6e 99 89 48 ec 6c 6c aa}  //weight: 2, accuracy: High
        $x_1_6 = "Microsoft\\Protect\\dumpchk.exe" ascii //weight: 1
        $x_1_7 = "Microsoft\\Protect\\dbgeng.dll" ascii //weight: 1
        $x_1_8 = "SysWOW64\\xpsrchvw.exe" ascii //weight: 1
        $x_1_9 = "~DFFEO4C.TMP" ascii //weight: 1
        $x_1_10 = "IClientDll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


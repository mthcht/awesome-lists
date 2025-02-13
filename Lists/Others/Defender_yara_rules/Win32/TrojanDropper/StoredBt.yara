rule TrojanDropper_Win32_StoredBt_A_2147638962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/StoredBt.A"
        threat_id = "2147638962"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "StoredBt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_2 = "if exist \"%s\" goto :repeat_del" ascii //weight: 1
        $x_1_3 = "run32w.bat" ascii //weight: 1
        $x_1_4 = "nt%d.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


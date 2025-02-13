rule TrojanDownloader_Win32_Swchopy_A_2147710494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swchopy.A!bit"
        threat_id = "2147710494"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swchopy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cilingirizmir.net/yunus/swchost.exe" wide //weight: 1
        $x_1_2 = "C:\\Windows.dll" wide //weight: 1
        $x_1_3 = "C:\\LinqBridge.dll" wide //weight: 1
        $x_1_4 = "C:\\Interop.NetFwTypeLib.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


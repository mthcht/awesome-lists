rule TrojanProxy_Win32_Faceold_A_2147630501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Faceold.gen!A"
        threat_id = "2147630501"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Faceold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ItIsTheEndOfTheWorldAndIFeelFine!" ascii //weight: 1
        $x_1_2 = "SPHW[FXLdVsn" ascii //weight: 1
        $x_1_3 = "cacls \"%s\" /E /C /G everyone:f" ascii //weight: 1
        $x_1_4 = "%s\\sysinfo32.dat" wide //weight: 1
        $x_1_5 = "\\wininit32.exe" wide //weight: 1
        $x_1_6 = "NtCloseStatus" ascii //weight: 1
        $x_1_7 = "winsta0\\default" wide //weight: 1
        $x_1_8 = "FACEOLD:\\%s" wide //weight: 1
        $x_1_9 = "Gue55~?" wide //weight: 1
        $x_1_10 = "5e7e8100" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}


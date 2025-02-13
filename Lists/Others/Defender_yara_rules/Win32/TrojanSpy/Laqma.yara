rule TrojanSpy_Win32_Laqma_A_2147598667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Laqma.A"
        threat_id = "2147598667"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Laqma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "254"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "%s\\system32\\%s" ascii //weight: 50
        $x_50_2 = ".\\LanManDrv" ascii //weight: 50
        $x_25_3 = "__intsrv32" ascii //weight: 25
        $x_25_4 = "__srvmgr32" ascii //weight: 25
        $x_25_5 = "%d.%d.%d.%d" ascii //weight: 25
        $x_25_6 = "www.google.com" ascii //weight: 25
        $x_10_7 = "qmopt.dll" ascii //weight: 10
        $x_10_8 = "wininet.dll" ascii //weight: 10
        $x_10_9 = "iexchg.dll" ascii //weight: 10
        $x_10_10 = "lanmanwrk.exe" ascii //weight: 10
        $x_10_11 = "rundll32.exe" ascii //weight: 10
        $x_1_12 = "jpegfile\\shell\\open\\command" ascii //weight: 1
        $x_1_13 = "Software\\Microsoft\\Internet Explorer" ascii //weight: 1
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_15 = "StartServiceA" ascii //weight: 1
        $x_1_16 = "OpenServiceA" ascii //weight: 1
        $x_1_17 = "CreateServiceA" ascii //weight: 1
        $x_1_18 = "ZwQueryService" ascii //weight: 1
        $x_1_19 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_20 = "InternetOpenA" ascii //weight: 1
        $x_1_21 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 4 of ($x_25_*) and 5 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Laqma_B_2147598671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Laqma.B"
        threat_id = "2147598671"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Laqma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 10 75 1f 81 7d 10 32 02 00 00 75 16 81 7d 14 65 a3 00 00 75 0d e8 ?? ?? 00 00 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d3 80 3e 21 75 37 80 7e 01 45 75 31 80 7e 02 58 75 2b 80 7e 03 21 75 25 51 8d 46 04 8b cc 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


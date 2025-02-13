rule TrojanDownloader_Win32_Somex_A_2147625245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Somex.A"
        threat_id = "2147625245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Somex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%s?mxdu=%s&mxdp=%s&p2=%d&B2=%d&N=%s&Q=%d&Key=%d&lang=%d" ascii //weight: 1
        $x_1_2 = "/Count.asp?mac=%s&ver=%s&os=%s&lang=%d" ascii //weight: 1
        $x_1_3 = "Agent%ld" ascii //weight: 1
        $x_1_4 = "InjectDll flunk" ascii //weight: 1
        $x_1_5 = "pol.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Somex_A_2147625245_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Somex.A"
        threat_id = "2147625245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Somex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%sex.dll" ascii //weight: 1
        $x_1_2 = "Manages the RPC name service load" ascii //weight: 1
        $x_1_3 = {00 42 49 4e 00 53 65 72 76 69 63 65 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "OpenSCManagerA" ascii //weight: 1
        $x_1_5 = "CreateServiceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Somex_B_2147664492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Somex.B"
        threat_id = "2147664492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Somex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%sex.dll" ascii //weight: 1
        $x_1_2 = "\\system\\config_shenghai.dat" ascii //weight: 1
        $x_1_3 = "ServiceDll /t REG_EXPAND_SZ /d %s" ascii //weight: 1
        $x_1_4 = "%s?action=exesuccess&hostid=%s" ascii //weight: 1
        $x_1_5 = "OutTimeOfYear" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


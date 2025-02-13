rule TrojanDownloader_Win32_AdoStream_A_2147596738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AdoStream.A"
        threat_id = "2147596738"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AdoStream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set HTTPGET = CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "Set SendBinary = CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_3 = "DataBin = HTTPGET.ResponseBody" ascii //weight: 1
        $x_1_4 = "Const adSaveCreateOverWrite=2" ascii //weight: 1
        $x_1_5 = "Const adTypeBinary=1" ascii //weight: 1
        $x_1_6 = "wscript.exe /B" ascii //weight: 1
        $x_1_7 = "cscript.exe /B" ascii //weight: 1
        $x_1_8 = "HTTPGET.Send" ascii //weight: 1
        $x_1_9 = "mshta.exe" ascii //weight: 1
        $x_1_10 = "VBScript" wide //weight: 1
        $x_1_11 = "Everstrike Software" ascii //weight: 1
        $x_1_12 = "ExeScript Host" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}


rule Trojan_Win32_Shaosmine_J_2147743090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shaosmine.J!ibt"
        threat_id = "2147743090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shaosmine"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 16 18 6f ?? 00 00 0a 72 ?? ?? 00 70 03 18 18 6f ?? 00 00 0a ?? ?? 00 00 0a 13}  //weight: 1, accuracy: Low
        $x_1_2 = "v1B2c3D4e5F6g7Ha" wide //weight: 1
        $x_1_3 = "HTTP.Open \"GET\", strLink, False" wide //weight: 1
        $x_1_4 = "If objFSO.FileExists(strSaveTo) Then" wide //weight: 1
        $x_1_5 = "objFSO.DeleteFile(strSaveTo)" wide //weight: 1
        $x_1_6 = ".Write objHTTP.ResponseBody" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shaosmine_AA_2147744701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shaosmine.AA!MTB"
        threat_id = "2147744701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shaosmine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WshShell = CreateObject(\"WScript.Shell\")" wide //weight: 1
        $x_1_2 = "strLink = \"download_link\"" wide //weight: 1
        $x_1_3 = "objStream = CreateObject(\"ADODB.Stream\")" wide //weight: 1
        $x_1_4 = "objHTTP.Open \"GET\", strLink, False" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


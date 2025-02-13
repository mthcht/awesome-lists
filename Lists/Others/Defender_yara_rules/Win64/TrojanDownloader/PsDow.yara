rule TrojanDownloader_Win64_PsDow_A_2147896321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/PsDow.A!MTB"
        threat_id = "2147896321"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd /c powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('%s', '%s');%s" ascii //weight: 2
        $x_2_2 = "cmd /c certutil.exe -urlcache -split -f %s %s&&%s" ascii //weight: 2
        $x_2_3 = "createobject(\"adodb.stream\"):set web=createobject(\"microsoft.xmlhttp\")" ascii //weight: 2
        $x_2_4 = "web.open \"get\",.arguments(0),0:web.send:if web.status" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


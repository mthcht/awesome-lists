rule BrowserModifier_Win32_InstaFinder_15078_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/InstaFinder"
        threat_id = "15078"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "InstaFinder"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download.instafinder.com" ascii //weight: 1
        $x_1_2 = "instafinder_installfull.exe" ascii //weight: 1
        $x_1_3 = "Instafinder LLC" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "HttpQueryInfoA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


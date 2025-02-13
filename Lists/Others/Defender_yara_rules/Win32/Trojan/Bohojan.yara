rule Trojan_Win32_Bohojan_A_2147692457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bohojan.A"
        threat_id = "2147692457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohojan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\aclient\\Log.txt" ascii //weight: 1
        $x_1_2 = "BotMain::onBeforeNavigate(" ascii //weight: 1
        $x_1_3 = "force_homepage" ascii //weight: 1
        $x_1_4 = "config downloader" ascii //weight: 1
        $x_1_5 = "Catching url for redirection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


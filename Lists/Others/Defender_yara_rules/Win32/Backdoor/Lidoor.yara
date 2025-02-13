rule Backdoor_Win32_Lidoor_A_2147595959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lidoor.A"
        threat_id = "2147595959"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://%s:%d/PUT[%s]/FC001/%s" ascii //weight: 2
        $x_2_2 = "kill cmd ok" ascii //weight: 2
        $x_2_3 = "http://%s:%d/FC001/%s" ascii //weight: 2
        $x_2_4 = "pandanlin.3322.org" ascii //weight: 2
        $x_2_5 = "60.248.79.226" ascii //weight: 2
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}


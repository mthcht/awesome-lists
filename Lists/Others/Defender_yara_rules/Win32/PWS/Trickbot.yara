rule PWS_Win32_Trickbot_N_2147766721_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Trickbot.N"
        threat_id = "2147766721"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grab_passwords_chrome()" ascii //weight: 1
        $x_1_2 = "from logins where blacklisted_by_user = 0" ascii //weight: 1
        $x_1_3 = "\\default\\login data.bak" ascii //weight: 1
        $x_1_4 = "mimikatz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Trickbot_O_2147766722_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Trickbot.O"
        threat_id = "2147766722"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mimikatz" wide //weight: 1
        $x_1_2 = {5b 72 65 66 6c 65 63 74 69 6f 6e 2e 61 73 73 65 6d 62 6c 79 5d 3a 3a 6c 6f 61 64 66 69 6c 65 28 22 [0-32] 5c 6b 65 65 70 61 73 73 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "MTIzNA==; cXdlcg==;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


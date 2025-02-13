rule Backdoor_Win32_Trubsil_A_2147682600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trubsil.A"
        threat_id = "2147682600"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trubsil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "%Silent_Bruter_Small" ascii //weight: 2
        $x_1_2 = "/wp-admin/plugin-install.php?tab=upload" ascii //weight: 1
        $x_1_3 = {62 00 72 00 75 00 74 00 65 00 72 00 65 00 73 00 2e 00 70 00 68 00 70 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 00 68 00 65 00 63 00 6b 00 72 00 65 00 73 00 2e 00 70 00 68 00 70 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 00 70 00 6c 00 6f 00 61 00 64 00 72 00 65 00 73 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "username=%s&passwd=%s&lang=&option=com_login&task=login&return=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Trubsil_B_2147682668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trubsil.B"
        threat_id = "2147682668"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trubsil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "username=%s&passwd=%s&lang=&option=com_login&task=login&%s=%s" wide //weight: 100
        $x_20_2 = "http://ku.ololo.in/bruteres.php" wide //weight: 20
        $x_10_3 = "log=%s&pwd=%s&redirect_to=%s&testcookie=" wide //weight: 10
        $x_10_4 = "subaction=dologin&username=%s&password=%s" wide //weight: 10
        $x_10_5 = "name=%s&pass=%s&form_id=user_login_block" wide //weight: 10
        $x_10_6 = "login_status=login&userident=%s&redirect_url=backend.php" wide //weight: 10
        $x_5_7 = "destination=admin/index.php" wide //weight: 5
        $x_5_8 = "Silent_Bruter" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Trubsil_C_2147688571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trubsil.C"
        threat_id = "2147688571"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trubsil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Silent_SMTP_Bruter" ascii //weight: 10
        $x_10_2 = "Spfuwbrf\\Nidrpspfu\\Xiodpwt\\DusrfnuVfrtipn]Rvn" wide //weight: 10
        $x_1_3 = "checkres.php" wide //weight: 1
        $x_1_4 = "bruteres.php" wide //weight: 1
        $x_1_5 = "emailcheckres.php" wide //weight: 1
        $x_1_6 = "{domaincut}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


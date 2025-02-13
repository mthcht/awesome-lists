rule PWS_PowerShell_LightSwipe_A_2147933292_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:PowerShell/LightSwipe.A!dha"
        threat_id = "2147933292"
        type = "PWS"
        platform = "PowerShell: "
        family = "LightSwipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\google\\\\chrome\\\\user data\\\\default\\\\login data" wide //weight: 1
        $x_1_2 = "\\\\google\\\\chrome\\\\user data\\\\local state" wide //weight: 1
        $x_1_3 = "\\\\microsoft\\\\edge\\\\user data\\\\default\\\\login data" wide //weight: 1
        $x_1_4 = "\\\\microsoft\\\\edge\\\\user data\\\\local state" wide //weight: 1
        $x_10_5 = "[system.security.cryptography.protecteddata]::Unprotect($master_key_encoded[5..$master_key_encoded" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Ransom_Win32_Tocrypt_C_2147696367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tocrypt.C"
        threat_id = "2147696367"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {84 c0 74 0f 2c 00 01 00 00 00 c7 44 ?? ?? 00 00 00 00 c7 04 ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 0e 00 00 00 e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0f c7 85 ?? ?? ?? ?? 01 00 00 00 e9}  //weight: 4, accuracy: Low
        $x_2_2 = "\\TOX RANSOM.html" ascii //weight: 2
        $x_1_3 = "\\tox.log" ascii //weight: 1
        $x_1_4 = "\\tox_tor\\" ascii //weight: 1
        $x_1_5 = ".toxcrypt" ascii //weight: 1
        $x_1_6 = "\\tox.done.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_PowerBypass_DA_2147938432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowerBypass.DA!MTB"
        threat_id = "2147938432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_1_2 = "AesCryptoServiceProvider" wide //weight: 1
        $x_1_3 = "[Reflection.Assembly]::Load" wide //weight: 1
        $x_1_4 = "CreateDecryptor()" wide //weight: 1
        $x_1_5 = "TransformFinalBlock($" wide //weight: 1
        $x_1_6 = "get-itemproperty 'HKCU:\\Software\\Classes\\" wide //weight: 1
        $x_1_7 = "@([byte]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


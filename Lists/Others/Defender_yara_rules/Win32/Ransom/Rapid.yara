rule Ransom_Win32_Rapid_A_2147730079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rapid.A!MTB"
        threat_id = "2147730079"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Do you really want to restore your files?" ascii //weight: 1
        $x_1_3 = "Write to our email - help@wizrac.com" ascii //weight: 1
        $x_1_4 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Rapid_PB_2147787567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rapid.PB!MTB"
        threat_id = "2147787567"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/Create /SC MINUTE /TN Encrypter /TR" ascii //weight: 10
        $x_10_2 = "/Create /SC ONLOGON /TN EncrypterSt /TR" ascii //weight: 10
        $x_5_3 = "!DECRYPT_FILES.txt" ascii //weight: 5
        $x_1_4 = "vmware-vmx.exe" ascii //weight: 1
        $x_1_5 = "thunderbird.exe" ascii //weight: 1
        $x_1_6 = "\\noputana.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


rule Ransom_Win32_RanzyLock_AA_2147785327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RanzyLock.AA!MTB"
        threat_id = "2147785327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RanzyLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".RANZYLOCKED" wide //weight: 1
        $x_1_2 = "44656C65746520536861646F7773202F416C6C202F5175696574" ascii //weight: 1
        $x_1_3 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550" ascii //weight: 1
        $x_1_4 = "wipe_me" wide //weight: 1
        $x_1_5 = "vmickvpexchange" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


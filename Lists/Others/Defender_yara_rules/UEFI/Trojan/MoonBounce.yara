rule Trojan_UEFI_MoonBounce_A_2147811012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:UEFI/MoonBounce.A"
        threat_id = "2147811012"
        type = "Trojan"
        platform = "UEFI: "
        family = "MoonBounce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 48 c7 40 01 89 5c 24 08}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 48 c7 40 01 8b c4 48 89}  //weight: 1, accuracy: High
        $x_1_3 = {7f 32 67 81 ?? ?? 41 55 48 cb 75}  //weight: 1, accuracy: Low
        $x_1_4 = {9c 51 50 4c 89 e8 48 ff c8 81 38 4d 5a 90 90 00 75 f5 e8}  //weight: 1, accuracy: High
        $x_1_5 = {c3 cc cc e8 ?? ?? ?? ?? ?? ?? ?? [0-7] 83 f9 0e 49 8b f8 48 8b f2 8b d9 7c}  //weight: 1, accuracy: Low
        $x_1_6 = {c3 cc cc e8 ?? ?? ?? ?? 56 48 83 ec 20 48 83 64 24 40 00 48 8b da 4c 8d 44 24 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


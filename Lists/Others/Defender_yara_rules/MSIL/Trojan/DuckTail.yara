rule Trojan_MSIL_DUCKTAIL_EH_2147846751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DUCKTAIL.EH!MTB"
        threat_id = "2147846751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DUCKTAIL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 82 3c ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0d ff e8 6f 1d ff fd ba 8a ff ff c2 95 ff e5 65 0e}  //weight: 10, accuracy: High
        $x_10_2 = {e2 d0 2e 73 b1 f1 13 86 61 82 99 c2 c2 42 3c d0 ac 3f b4 e8 64 9b 04 f0 42 1c 3e 18 b0 d0 f8 09 c3 30 c1 4c ee d9 0b b8 bf 29 05 c0 30 9e 0c 05}  //weight: 10, accuracy: High
        $x_10_3 = {12 12 d6 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 22 22 d9 ff}  //weight: 10, accuracy: High
        $x_10_4 = {ee 0b 02 ba 4b b8 56 45 30 c8 12 20 01 54 c8 13 58 90 07 2b 72 ac 20 ee 2a 82 11 24 1c a2 b0 10 10 64 63 60 51 21 18 c2 25 90 10 89 86 74 f5 31}  //weight: 10, accuracy: High
        $x_1_5 = "hijackLockHolder.Acquired." ascii //weight: 1
        $x_1_6 = "Corehost.Static\\singlefilehost.pdb" ascii //weight: 1
        $x_1_7 = "CreateMemoryResourceNotification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DUCKTAIL_EH_2147846751_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DUCKTAIL.EH!MTB"
        threat_id = "2147846751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DUCKTAIL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/{CYR}.txt" wide //weight: 1
        $x_1_2 = "/{LOG}.txt" wide //weight: 1
        $x_1_3 = "/{CFG}.txt" wide //weight: 1
        $x_1_4 = "/{PRS}.txt" wide //weight: 1
        $x_1_5 = "/{SCR}.jpg" wide //weight: 1
        $x_1_6 = "/{PAW" wide //weight: 1
        $x_1_7 = "/{HIY" wide //weight: 1
        $x_1_8 = "/{DWN" wide //weight: 1
        $x_1_9 = "Telegram.Bot" ascii //weight: 1
        $x_1_10 = "AesEncrypt" ascii //weight: 1
        $x_1_11 = "yi9lc7Zc5ExJqJ26pkdCFM0dVVIoqn/Ls4+3DTzc61s=" wide //weight: 1
        $x_1_12 = "wPia8bz26WHe35ITidhnrzU7LVppovtwJ6ncYVua3WM=" wide //weight: 1
        $x_1_13 = "browser_headers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DUCKTAIL_EM_2147895025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DUCKTAIL.EM!MTB"
        threat_id = "2147895025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DUCKTAIL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DUCITA.Helpers" ascii //weight: 1
        $x_1_2 = "SDCBundle.Helpers" ascii //weight: 1
        $x_1_3 = "get_c03p1_2" ascii //weight: 1
        $x_1_4 = "TL+eh8OWgVJtM/rwptBV1Rg9ej/MnDpxY+MhsGgO8hM=" ascii //weight: 1
        $x_1_5 = "tkfgk435jkdgf.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


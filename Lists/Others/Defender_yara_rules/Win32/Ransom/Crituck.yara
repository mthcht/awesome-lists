rule Ransom_Win32_Crituck_A_2147718314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crituck.A"
        threat_id = "2147718314"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crituck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c ping 1.1.1.1 -n 1 -w" ascii //weight: 1
        $x_1_2 = "info_%.8X.info" ascii //weight: 1
        $x_1_3 = "CryptoLuck_Instance" ascii //weight: 1
        $x_1_4 = "\\sosad_%.8X" ascii //weight: 1
        $x_1_5 = "goopdate.dll" ascii //weight: 1
        $x_2_6 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoamWzd2h7DKzMKYAhdJ" ascii //weight: 2
        $x_1_7 = "%s %s%s KEY-----" ascii //weight: 1
        $x_1_8 = "shadows /all" ascii //weight: 1
        $x_1_9 = {00 6e 65 77 77 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 74 6c 65 66 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 63 72 70 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_12 = "/addressbalance/%s?confirmations=%d" ascii //weight: 1
        $x_1_13 = "%s?id=%.8X&getpm" ascii //weight: 1
        $x_1_14 = "MsgNotAll" ascii //weight: 1
        $x_1_15 = "MsgFileSaved" ascii //weight: 1
        $x_1_16 = "%s_%.8X.qr.png" ascii //weight: 1
        $x_1_17 = "?data=bitcoin:%s" ascii //weight: 1
        $x_1_18 = "?amount=%s&size=" ascii //weight: 1
        $x_1_19 = "BTN_Browse" ascii //weight: 1
        $x_1_20 = "MsgPKNotFound" ascii //weight: 1
        $x_1_21 = "MsgPKNotValid" ascii //weight: 1
        $x_2_22 = {80 38 70 75 ?? 80 78 01 6d 75 ?? 80 78 02 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


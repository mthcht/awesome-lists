rule Backdoor_Win64_GoDropper_A_2147778611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/GoDropper.A"
        threat_id = "2147778611"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "GoDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/ProtonMail/gopenpgp" ascii //weight: 1
        $x_1_2 = "main.CopyBinary" ascii //weight: 1
        $x_1_3 = "main.GetBinStoreRoot" ascii //weight: 1
        $x_1_4 = "sCHtAsks.exe" ascii //weight: 1
        $x_1_5 = "/query" ascii //weight: 1
        $x_1_6 = "main.CheckPersistence" ascii //weight: 1
        $x_1_7 = "goos" ascii //weight: 1
        $x_1_8 = "main.GetBinStoreUser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


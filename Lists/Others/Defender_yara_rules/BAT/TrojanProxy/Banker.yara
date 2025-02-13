rule TrojanProxy_BAT_Banker_G_2147679140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:BAT/Banker.G"
        threat_id = "2147679140"
        type = "TrojanProxy"
        platform = "BAT: Basic scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".db\" (start /low /min iexplore.exe \"http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


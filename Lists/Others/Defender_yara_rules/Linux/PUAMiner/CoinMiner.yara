rule PUAMiner_Linux_CoinMiner_409805_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUAMiner:Linux/CoinMiner!xmrig"
        threat_id = "409805"
        type = "PUAMiner"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "xmrig: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "46QBumovWy4dLJ4R8wq8JwhHKWMhCaDyNDEzvxHFmAHn92EyKrttq6LfV6if5UYDAyCzh3egWXMhnfJJrEhWkMzqTPzGzsE" ascii //weight: 1
        $x_1_2 = "44EspGiviPdeZSZyX1r3R9RhpGCkxYACEKUwbA4Gp6cVCzyiNeB21STWYsJZYZeZt63JaUn8CVxDeWWGs3f6XNxGPtSuUEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


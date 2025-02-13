rule TrojanDropper_W97M_Omega_2147691012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Omega"
        threat_id = "2147691012"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Omega"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bml0VXJsIDogJ2Fib3V0OmJsYW5rJywNCglqbXBVcmxMaXN0IDogWydodHRwOi8vbWFpbC52aXRhbWlubWFpbi5pbmZvL2luYzEu" ascii //weight: 1
        $x_1_2 = "cGhwJywnaHR0cDovLzE3Ni45LjE5NC4xMjQvaW5jMS5waHAnLCdodHRwOi8vaXRwMzAwLnVzYy5lZHUvZGVudC90ZXN0Mi5waHAn" ascii //weight: 1
        $x_1_3 = "ZW50LmRvY3VtZW50RWxlbWVudCl7V1NjcmlwdC5TbGVlcCgxMDAwKTt9DQoJCQkNCgkJCWZvcig7Oyl7DQoJCQkJV1NjcmlwdC5T" ascii //weight: 1
        $x_1_4 = "bGVlcCgxMDI0KTsNCgkJCQl2YXIgc25kID0gdGhpcy5JRS5kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic25kIik7DQoJCQkJdmFy" ascii //weight: 1
        $x_1_5 = "IHJjdiA9IHRoaXMuSUUuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJjdiIpOw0KCQkJCWlmKHNuZCAmJiByY3YpDQoJCQkJew0K" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Worm_Win32_Protoride_DJ_2147600118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Protoride.DJ"
        threat_id = "2147600118"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Protoride"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "12!Skanner" ascii //weight: 1
        $x_1_2 = "12 No pude crear el archivo \"%s\" (En uso?)" ascii //weight: 1
        $x_1_3 = "if not exist \"\"%*\"\" goto done" ascii //weight: 1
        $x_1_4 = "12 Uploaded!: %i.%i.%i.%i:%u : \"%s%s\" (%.1fkb \\ %.1fkb/s)" ascii //weight: 1
        $x_1_5 = "12 Error abriendo Wininet!" ascii //weight: 1
        $x_1_6 = "12 Falso Netbus" ascii //weight: 1
        $x_1_7 = "\\ipc$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


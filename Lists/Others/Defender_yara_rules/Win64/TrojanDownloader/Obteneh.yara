rule TrojanDownloader_Win64_Obteneh_A_2147905703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Obteneh.A!dha"
        threat_id = "2147905703"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Obteneh"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.primer_paso" ascii //weight: 1
        $x_1_2 = "main.un_zip" ascii //weight: 1
        $x_1_3 = "main.procesar" ascii //weight: 1
        $x_1_4 = "main.mostrar_progreso" ascii //weight: 1
        $x_1_5 = "main.obtener_zip.func1" ascii //weight: 1
        $x_1_6 = "C:/windows_update/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


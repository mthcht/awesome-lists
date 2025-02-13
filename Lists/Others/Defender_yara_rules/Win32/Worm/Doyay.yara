rule Worm_Win32_Doyay_A_2147608366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Doyay.A"
        threat_id = "2147608366"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Doyay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "..:: IP-WoRM WuZ HeRE ::.." ascii //weight: 1
        $x_1_2 = "Maaf. Akses anda untuk membuka Gambar/Film Porno telah kami batasi. Klik tombol YES apabila anda setuju dengan pembatasan ini, atau klik NO apabila anda " ascii //weight: 1
        $x_1_3 = "\\YaDoY SoFtWaRe DeVeLoPmEnT\\FOR PERBANAS\\ForSkripsi\\Viri\\ForSkripsi.vbp" wide //weight: 1
        $x_1_4 = {6b 00 31 00 63 00 6b 00 74 00 68 00 33 00 77 00 30 00 72 00 6d 00 [0-16] 6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


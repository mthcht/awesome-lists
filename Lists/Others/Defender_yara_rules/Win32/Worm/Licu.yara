rule Worm_Win32_Licu_2147580883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Licu"
        threat_id = "2147580883"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Licu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Javier\\Apolo5" ascii //weight: 1
        $x_1_2 = ".ao.br.cv.mo.mz.pt.st" ascii //weight: 1
        $x_1_3 = ".am.at.de.dk.ee.li.lu." ascii //weight: 1
        $x_1_4 = ".com.net.org.edu.gov.mil" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Records\\" ascii //weight: 1
        $x_1_6 = "FileToKill" ascii //weight: 1
        $x_1_7 = "RegFileKilled" ascii //weight: 1
        $x_1_8 = "AdressList" ascii //weight: 1
        $x_1_9 = "MIME-Version: 1.0" ascii //weight: 1
        $x_1_10 = "Content-Type: multipart/mixed;" ascii //weight: 1
        $x_1_11 = "----=_NextPart_000_0002_01BD22EE.C1291DA0" ascii //weight: 1
        $x_1_12 = "boundary=\"" ascii //weight: 1
        $x_1_13 = "X-Priority: 3" ascii //weight: 1
        $x_1_14 = "X-MSMail - Priority: Normal" ascii //weight: 1
        $x_1_15 = "X-MimeOLE: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" ascii //weight: 1
        $x_1_16 = "filename=\"" ascii //weight: 1
        $x_1_17 = "Esto es un mensaje multiparte en formato MIME" ascii //weight: 1
        $x_1_18 = "Content-Type: text/plain;" ascii //weight: 1
        $x_1_19 = "charset=\"x-user-defined\"" ascii //weight: 1
        $x_1_20 = "Content-Transfer-Encoding: 8bit" ascii //weight: 1
        $x_1_21 = "Content-Type: application/octet-stream;" ascii //weight: 1
        $x_1_22 = "Content-Disposition: attachment;" ascii //weight: 1
        $x_1_23 = "Content-Transfer-Encoding: base64" ascii //weight: 1
        $x_1_24 = "255.255.255.255" ascii //weight: 1
        $x_1_25 = "Error setting linger info:" ascii //weight: 1
        $x_1_26 = "c:\\windows\\GAMES" ascii //weight: 1
        $x_1_27 = "*shar*" ascii //weight: 1
        $x_1_28 = "net share GAMES=c:\\windows\\GAMES /unlimited" ascii //weight: 1
        $x_1_29 = "c$\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_30 = "c$\\Documents and Settings\\All Users\\Men" ascii //weight: 1
        $x_1_31 = "Inicio\\Programas\\Inicio" ascii //weight: 1
        $x_1_32 = "c$\\Windows\\All Users\\Start Menu\\Programs\\StartUp" ascii //weight: 1
        $x_1_33 = "c$\\Windows\\All Users\\Men" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (28 of ($x*))
}


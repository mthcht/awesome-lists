rule Virus_Win32_VB_AZ_2147581363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/VB.AZ"
        threat_id = "2147581363"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "     __________-=YOU SEE BEE CREW=-__________" wide //weight: 1
        $x_1_2 = "Black_Plankton" wide //weight: 1
        $x_1_3 = "{Y479C6D0-OTRW-U5GH-S1EE-E0AC10B4E666}" wide //weight: 1
        $x_1_4 = "{F146C9B1-VMVQ-A9RC-NUFL-D0BA00B4E999}" wide //weight: 1
        $x_1_5 = "net user MatriX shadow /add" wide //weight: 1
        $x_1_6 = "net localgroup administrators MatriX /add" wide //weight: 1
        $x_1_7 = "You See Bee Corporation" wide //weight: 1
        $x_1_8 = "net send * You See Bee Crew Was Here!!" wide //weight: 1
        $x_1_9 = "net send * Orang Pinter Lanjut ke soal berikutnya karena telor dan ayam" wide //weight: 1
        $x_1_10 = "http://www.blackplankton.cjb.net" wide //weight: 1
        $x_1_11 = "<title>Fucking Love_Fucking Friend</title>" wide //weight: 1
        $x_1_12 = "\\Pahami Cinta.txt" wide //weight: 1
        $x_1_13 = "\\Favorites\\Kampus Cinta.exe /register" wide //weight: 1
        $x_1_14 = "Black_Plankton@YouSeeBee" wide //weight: 1
        $x_1_15 = "Software\\Microsoft\\Windows\\ShellNoRocar temen sendiri, benar ato salah?" wide //weight: 1
        $x_1_16 = "Anda Salah!! Anda ga Cocok punya temen!!. Bubye for today..." wide //weight: 1
        $x_1_17 = "Musibah gempa jogja merengut nyawa 10rb jiwa, benar ato salah?" wide //weight: 1
        $x_1_18 = "Anda Salah!! Kebanyakan tuh mas!! ga kasian apa!!. Bubye for today..." wide //weight: 1
        $x_1_19 = "Processor socket 775 support d motherboard socket 478, benar ato salah?" wide //weight: 1
        $x_1_20 = "Anda Salah!! mana mungkin bisa! processor 775 ga ada kakinya koq!. Bubye for today..." wide //weight: 1
        $x_1_21 = "kalo qta punya temen brengsek, harus kita hajar!!, benar ato salah?" wide //weight: 1
        $x_1_22 = "Anda Salah!! Jangan donk! Gitu2 dya juga temen kita. biarin dya kena kharmaphala. Bubye for today..." wide //weight: 1
        $x_1_23 = "Telor ama ayam yang duluan ada ayam, bener ato salah" wide //weight: 1
        $x_1_24 = "Anda Merasa terganggu dengan Adanya banyak virus2 lokal?" wide //weight: 1
        $x_1_25 = "Hemm,... Makanya jadi orang harus teliti!! jangan asal klik. Gini dah akibatnya!! Bubye for today..." wide //weight: 1
        $x_1_26 = "Wah, anda benar2 mendukung kebangkitan programmer2 baru indonesia. Awal sukses dari jahil2 kaya gini toh!!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

rule Virus_Win32_VB_CV_2147594472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/VB.CV"
        threat_id = "2147594472"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Shut Down After 15 mins" wide //weight: 10
        $x_10_2 = "\\Desktop Backups\\VBM\\VBP\\Virus\\" wide //weight: 10
        $x_10_3 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_1_4 = "LimitPro" ascii //weight: 1
        $x_1_5 = "Limit.exe" wide //weight: 1
        $x_1_6 = "RunMe" ascii //weight: 1
        $x_1_7 = "ShutMsg" ascii //weight: 1
        $x_1_8 = "ShutDown" ascii //weight: 1
        $x_1_9 = "GetAbsNam" ascii //weight: 1
        $x_1_10 = "Distribute" ascii //weight: 1
        $x_5_11 = "Check=LimitPro" ascii //weight: 5
        $x_5_12 = "deletefile" wide //weight: 5
        $x_5_13 = "deletefolder" wide //weight: 5
        $x_1_14 = "C:\\windows\\regedit.exe" wide //weight: 1
        $x_1_15 = "C:\\windows\\system32\\cmd.exe" wide //weight: 1
        $x_1_16 = "C:\\windows\\system32\\command.com" wide //weight: 1
        $x_1_17 = "C:\\windows\\system32\\taskmgr.exe" wide //weight: 1
        $x_1_18 = "C:\\WINDOWS\\system32\\dllcache\\cmd.exe" wide //weight: 1
        $x_1_19 = "C:\\WINDOWS\\system32\\dllcache\\command.com" wide //weight: 1
        $x_1_20 = "C:\\WINDOWS\\system32\\dllcache\\taskmgr.exe" wide //weight: 1
        $x_1_21 = "C:\\WINDOWS\\system32\\dllcache\\regedit.exe" wide //weight: 1
        $x_1_22 = "C:\\WINDOWS\\system32\\dllcache\\msconfig.exe" wide //weight: 1
        $x_1_23 = "C:\\WINDOWS\\pchealth\\helpctr\\binaries\\msconfig.exe" wide //weight: 1
        $x_1_24 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_2_25 = "AdjustTokenPrivileges" ascii //weight: 2
        $x_2_26 = "OpenProcessToken" ascii //weight: 2
        $x_1_27 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_4_28 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" wide //weight: 4
        $x_1_29 = "[autorun]" wide //weight: 1
        $x_1_30 = "autorun.inf" wide //weight: 1
        $x_2_31 = "shellexecute=" wide //weight: 2
        $x_2_32 = "shell\\auto\\command=" wide //weight: 2
        $x_2_33 = "shell\\open\\command=" wide //weight: 2
        $x_2_34 = "shell\\explore\\command=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_5_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_VB_CZ_2147600203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/VB.CZ"
        threat_id = "2147600203"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Scheidenpilz" ascii //weight: 1
        $x_1_2 = "\\*.exe" wide //weight: 1
        $x_1_3 = "\\*.*" wide //weight: 1
        $x_1_4 = {c7 85 50 ff ff ff ?? ?? ?? ?? 6a 08 5e 89 b5 48 ff ff ff 8d 95 48 ff ff ff 8d 4d a8 e8 1e e8 ff ff c7 85 60 ff ff ff ?? ?? ?? ?? 89 b5 58 ff ff ff 8d 95 58 ff ff ff 8d 4d b8 e8 ?? ?? ff ff 8d 45 d4 89 85 70 ff ff ff c7 85 68 ff ff ff 0b 40 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


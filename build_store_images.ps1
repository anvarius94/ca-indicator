# build_store_images.ps1 - Собирает материалы карточки Chrome Web Store из
# скриншотов попапа: три изображения 1280x800 и обязательную промо-плитку 440x280.
#
# Запуск:  powershell -ExecutionPolicy Bypass -File build_store_images.ps1
#
# Только Windows: рисование текста требует System.Drawing и системных шрифтов,
# в Node без внешних зависимостей это не сделать. Файл сохранён с BOM —
# PowerShell 5.1 иначе читает кириллицу как ANSI и падает на разборе.
#
# Исходники берутся из screenshots/, результат кладётся в store/.

Add-Type -AssemblyName System.Drawing

$root = "d:\Documents\Anvar\CA Indicator"
$shots = Join-Path $root "screenshots"
$outDir = Join-Path $root "store"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Палитра взята из popup.css, чтобы карточки магазина не спорили с самим расширением
$bg        = [System.Drawing.ColorTranslator]::FromHtml("#0a0e17")
$panel     = [System.Drawing.ColorTranslator]::FromHtml("#131a29")
$textMain  = [System.Drawing.ColorTranslator]::FromHtml("#f1f5f9")
$textSec   = [System.Drawing.ColorTranslator]::FromHtml("#94a3b8")
$green     = [System.Drawing.ColorTranslator]::FromHtml("#22c55e")
$amber     = [System.Drawing.ColorTranslator]::FromHtml("#f59e0b")
$red       = [System.Drawing.ColorTranslator]::FromHtml("#ef4444")
$blue      = [System.Drawing.ColorTranslator]::FromHtml("#38bdf8")

function New-Shot {
    param(
        [string]$ShotFile, [string]$Title, [string[]]$Lines,
        [System.Drawing.Color]$Accent, [string]$OutFile
    )

    $W = 1280; $H = 800
    $bmp = New-Object System.Drawing.Bitmap $W, $H
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.TextRenderingHint = 'ClearTypeGridFit'
    $g.Clear($bg)

    # Мягкое пятно акцентного цвета за скриншотом
    $glow = New-Object System.Drawing.Drawing2D.GraphicsPath
    $glow.AddEllipse(-120, 120, 760, 720)
    $pgb = New-Object System.Drawing.Drawing2D.PathGradientBrush $glow
    $pgb.CenterColor = [System.Drawing.Color]::FromArgb(38, $Accent.R, $Accent.G, $Accent.B)
    $pgb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $Accent.R, $Accent.G, $Accent.B))
    $g.FillPath($pgb, $glow)
    $pgb.Dispose(); $glow.Dispose()

    # Скриншот попапа слева, вписан по высоте
    $src = [System.Drawing.Image]::FromFile((Join-Path $shots $ShotFile))
    $maxH = 680
    $scale = $maxH / $src.Height
    $dw = [int]($src.Width * $scale); $dh = [int]($src.Height * $scale)
    $dx = 90; $dy = [int](($H - $dh) / 2)

    $shadow = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(90, 0, 0, 0))
    $g.FillRectangle($shadow, ($dx + 8), ($dy + 10), $dw, $dh)
    $shadow.Dispose()
    $g.DrawImage($src, $dx, $dy, $dw, $dh)
    $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(46, 255, 255, 255)), 1
    $g.DrawRectangle($borderPen, $dx, $dy, $dw, $dh)
    $borderPen.Dispose()
    $src.Dispose()

    # Текстовая колонка справа
    $tx = $dx + $dw + 70
    $tw = $W - $tx - 80

    $fTitle = New-Object System.Drawing.Font("Segoe UI Semibold", 34, [System.Drawing.FontStyle]::Bold)
    $fBody  = New-Object System.Drawing.Font("Segoe UI", 19)
    $bTitle = New-Object System.Drawing.SolidBrush $Accent
    $bBody  = New-Object System.Drawing.SolidBrush $textSec

    $fmt = New-Object System.Drawing.StringFormat
    $rectTitle = New-Object System.Drawing.RectangleF $tx, 210, $tw, 200
    $g.DrawString($Title, $fTitle, $bTitle, $rectTitle, $fmt)

    $titleH = $g.MeasureString($Title, $fTitle, $tw).Height
    $y = 210 + $titleH + 28
    foreach ($line in $Lines) {
        $r = New-Object System.Drawing.RectangleF $tx, $y, $tw, 400
        $g.DrawString($line, $fBody, $bBody, $r, $fmt)
        $y += $g.MeasureString($line, $fBody, $tw).Height + 18
    }

    # Подпись расширения внизу
    $fName = New-Object System.Drawing.Font("Segoe UI Semibold", 17, [System.Drawing.FontStyle]::Bold)
    $bName = New-Object System.Drawing.SolidBrush $blue
    $g.DrawString("CA Indicator", $fName, $bName, $tx, ($H - 110))
    $fName.Dispose(); $bName.Dispose()

    $fTitle.Dispose(); $fBody.Dispose(); $bTitle.Dispose(); $bBody.Dispose()
    $g.Dispose()
    $bmp.Save((Join-Path $outDir $OutFile), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "  $OutFile  1280x800"
}

Write-Output "Скриншоты для магазина:"

New-Shot -ShotFile "public-ca.png" `
    -Title "Сертификат публичного центра" `
    -Lines @(
        "В сертификате есть подписи Certificate Transparency. Их выдают только публично доверенным центрам, поэтому локально установленный корень такой сертификат подделать не может.",
        "Цепочка достраивается до корня из Chrome Root Store, все подписи проверяются криптографически."
    ) -Accent $green -OutFile "screenshot-1-public.png"

New-Shot -ShotFile "invalid-cert.png" `
    -Title "Браузер забраковал сертификат" `
    -Lines @(
        "Сертификат просрочен, отозван, самоподписан или выдан не на этот домен.",
        "Расширение ничего не блокирует: сайт открывается как обычно, вы просто видите, чем именно он защищён."
    ) -Accent $red -OutFile "screenshot-2-invalid.png"

New-Shot -ShotFile "whitelisted.png" `
    -Title "Ваше исключение для домена" `
    -Lines @(
        "Свой сервер можно разрешить вручную. Доверие привязано к паре «домен + сертификат»: на других доменах он доверенным не считается.",
        "Если сертификат на этом домене подменят, предупреждение вернётся."
    ) -Accent $amber -OutFile "screenshot-3-whitelist.png"

# ---------- Промо-плитка 440x280 ----------
$W = 440; $H = 280
$bmp = New-Object System.Drawing.Bitmap $W, $H
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.InterpolationMode = 'HighQualityBicubic'
$g.TextRenderingHint = 'ClearTypeGridFit'

$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Rectangle 0, 0, $W, $H), $bg, $panel, 45.0)
$g.FillRectangle($grad, 0, 0, $W, $H)
$grad.Dispose()

$icon = [System.Drawing.Image]::FromFile((Join-Path $root "icons\icon-trusted-128.png"))
$g.DrawImage($icon, 28, 44, 84, 84)
$icon.Dispose()

$fT = New-Object System.Drawing.Font("Segoe UI Semibold", 25, [System.Drawing.FontStyle]::Bold)
$bT = New-Object System.Drawing.SolidBrush $textMain
$g.DrawString("CA Indicator", $fT, $bT, 126, 48)
$fT.Dispose(); $bT.Dispose()

$fS = New-Object System.Drawing.Font("Segoe UI", 12)
$bS = New-Object System.Drawing.SolidBrush $blue
$g.DrawString("Кто на самом деле подписал сайт", $fS, $bS, 128, 92)
$fS.Dispose(); $bS.Dispose()

$fB = New-Object System.Drawing.Font("Segoe UI", 12.5)
$bB = New-Object System.Drawing.SolidBrush $textSec
$r = New-Object System.Drawing.RectangleF 28, 156, ($W - 56), 100
$g.DrawString("Публичный удостоверяющий центр — или корень, установленный на вашем компьютере. Ничего не блокирует.", $fB, $bB, $r)
$fB.Dispose(); $bB.Dispose()

$pen = New-Object System.Drawing.Pen $green, 3
$g.DrawLine($pen, 28, 140, 96, 140)
$pen.Dispose()

$g.Dispose()
$bmp.Save((Join-Path $outDir "promo-440x280.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "Промо-плитка:"
Write-Output "  promo-440x280.png  440x280"

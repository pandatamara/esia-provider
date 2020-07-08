<?php

/**
 * Класс для консолькольной подписи запросов с помощью утилиты Openssl
 */

namespace Esia\Signer;

use Esia\Signer\Exceptions\SignFailException;
use Psr\Log\LoggerAwareTrait;

class CliOpensslSigner extends AbstractSignerPKCS7 implements SignerInterface
{
    use LoggerAwareTrait;

    /**
     * @param string $message
     * @return string
     * @throws SignFailException
     */

    public function sign(string $message): string
    {
        $this->checkFilesExists();

        // random unique directories for sign
        $messageFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        $signFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        file_put_contents($messageFile, $message);

        //echo '<pre>';

        /**
         * Тестовая история
         */

        /*var_dump('/opt/cprocsp/bin/amd64/cryptcp -sign
        -thumbprint 10882bdfe1bd7f2192bafa96c14e4b2e5871d951 -nochain -der /var/www/lk_tfomskbr/sys-temp/tmp/acac56854821c6ced41a9e5d27935fc9 
        /var/www/lk_tfomskbr/sys-temp/tmp/ef4b0d1bb8ab36c40839f1cbfac0ea14');*/

        /*var_dump('БЕЗ PIN');
        var_dump(
            '/opt/cprocsp/bin/amd64/cryptcp -sign -thumbprint 10882bdfe1bd7f2192bafa96c14e4b2e5871d951 -nochain -der ' .
            ' ' . escapeshellarg($messageFile) . ' ' .
            ' ' . escapeshellarg($signFile)
        );

        var_dump('С ПУСТЫМ PIN');
        var_dump(
            '/opt/cprocsp/bin/amd64/cryptcp -sign -thumbprint 10882bdfe1bd7f2192bafa96c14e4b2e5871d951 -nochain -pin -der ' .
            ' ' . escapeshellarg($messageFile) . ' ' .
            ' ' . escapeshellarg($signFile)
        );

        die();*/

        /*$this->run(
            'openssl ' .
            'smime -engine gostengy -sign -binary -outform DER -noattr ' .
            '-signer ' . escapeshellarg($this->certPath) . ' ' .
            '-inkey ' . escapeshellarg($this->privateKeyPath) . ' ' .
            '-passin ' . escapeshellarg('pass:' . $this->privateKeyPassword) . ' ' .
            '-in ' . escapeshellarg($messageFile) . ' ' .
            '-out ' . escapeshellarg($signFile)
        );*/

        /*echo '<pre>';
        var_dump('/opt/cprocsp/bin/amd64/cryptcp -sign -thumbprint 10882bdfe1bd7f2192bafa96c14e4b2e5871d951 -nochain -der ' .
            ' ' . escapeshellarg($messageFile) . ' ' .
            ' ' . escapeshellarg($signFile));

        var_dump('Сертификаты');
        var_dump(shell_exec("/opt/cprocsp/bin/amd64/certmgr -list"));*/

        $this->run(
            '/opt/cprocsp/bin/amd64/cryptcp -sign -thumbprint 10882bdfe1bd7f2192bafa96c14e4b2e5871d951 -nochain -der ' .
            ' ' . escapeshellarg($messageFile) . ' ' .
            ' ' . escapeshellarg($signFile)
        );


        $signed = file_get_contents($signFile);
        if ($signed === false) {
            $message = sprintf('cannot read %s file', $signFile);
            $this->logger->error($message);
            throw new SignFailException($message);
        }
        $sign = $this->urlSafe(base64_encode($signed));

        unlink($signFile);
        unlink($messageFile);
        return $sign;
    }

    /**
     * @param $command
     * @return void
     * @throws SignFailException
     */
    private function run(string $command): void
    {
        $process = proc_open(
            $command,
            [
                ['pipe', 'w'], // stdout
                ['pipe', 'w'], // stderr
            ],
            $pipes
        );

        $result = stream_get_contents($pipes[0]);
        fclose($pipes[0]);

        $errors = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $code = proc_close($process);
        /*var_dump($code);
        die();*/
        if (0 !== $code || $result === false) {
            $errors = $errors ?: 'unknown';
            $this->logger->error('Sign fail');
            $this->logger->error('SSL error: ' . $errors);
            throw new SignFailException($errors);
        }
    }
}

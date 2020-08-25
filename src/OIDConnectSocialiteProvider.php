<?php

namespace Furdarius\OIDConnect;

use Furdarius\OIDConnect\Exception\TokenRequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Lcobucci\JWT\Parser;

class OIDConnectSocialiteProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid'
    ];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * JWT Token parser instance.
     *
     * @var \Lcobucci\JWT\Parser
     */
    protected $parser;
    /**
     * @var string
     */
    private $authUrl;
    /**
     * @var string
     */
    private $tokenUrl;

    /**
     * Create a new provider instance.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Lcobucci\JWT\Parser     $parser
     * @param  string                   $clientId
     * @param  string                   $clientSecret
     * @param  string                   $redirectUrl
     * @param  string                   $authUrl
     * @param  string                   $tokenUrl
     */
    public function __construct(
        Request $request,
        Parser $parser,
        string $clientId,
        string $clientSecret,
        string $redirectUrl,
        string $authUrl,
        string $tokenUrl
    ) {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);

        $this->parser = $parser;
        $this->authUrl = $authUrl;
        $this->tokenUrl = $tokenUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        if (!empty($response['error'])) {
            throw new TokenRequestException($response['error']);
        }

        $token = $response['access_token'];

        $user = $this->mapUserToObject($this->getUserByToken($token));

        return $user->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'],
            'sub' => $user['sub'],
            'iss' => $user['iss'],
            'first_name' => $user['given_name'],
            'last_name' => $user['family_name'],
            'name' => $user['name'],
            'email' => ( isset( $user['email'] ) ? $user['email'] : '' ),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        /**
         * We cant get claims from Token interface, so call claims method implicitly
         * link: https://github.com/lcobucci/jwt/pull/186
         *
         * @var $plainToken \Lcobucci\JWT\Token\Plain
         */
        $plainToken = $this->parser->parse($token);

        $client = new \GuzzleHttp\Client(['base_uri' => env('SURFCONEXT_BASE_URI')]);

        $res = $client->request('GET', ' userinfo', [
            'allow_redirects' => true,
            'headers' => [
                'Authorization' => 'Bearer ' . $token
            ]
        ]);
        $userData = json_decode($res->getBody(), true);

        $userData['iss'] = $plainToken->getClaim('iss');
        // 302

        return $userData;
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->authUrl, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->tokenUrl;
    }
}

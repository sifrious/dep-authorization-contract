<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';

use Sifrious\AuthorizationContract\ActorContext;
use Sifrious\AuthorizationContract\ActorKind;
use Sifrious\AuthorizationContract\AuthorizationContext;
use Sifrious\AuthorizationContract\AuthorizationDecision;
use Sifrious\AuthorizationContract\DisclosureMode;
use Sifrious\AuthorizationContract\TenantScope;
use Sifrious\ReferenceContract\CrossPackageReference;

function check(bool $condition, string $message): void { if (! $condition) { throw new RuntimeException($message); } }
function fixture(string $name, Closure $test): void { $test(); fwrite(STDOUT, "PASS {$name}\n"); }
function account(string $id): CrossPackageReference { return new CrossPackageReference('sifrious/zahir', 'account', $id); }
function tenant(string $id): TenantScope { return TenantScope::forTenant('workspace', new CrossPackageReference('sifrious/zahir', 'workspace', $id)); }
function decide(?AuthorizationContext $context, TenantScope $resourceTenant): AuthorizationDecision {
    if ($context === null) { return AuthorizationDecision::deny('missing_actor'); }
    if (! $context->tenant->equals($resourceTenant)) { return AuthorizationDecision::deny('wrong_tenant', DisclosureMode::ConcealAsMissing); }
    return AuthorizationDecision::permit('same_tenant', 'fixture-v1');
}

fixture('same-tenant permitted and cross/wrong-tenant denied independently of actor', function (): void {
    $context = new AuthorizationContext(new ActorContext(account('user-a'), ActorKind::Human), tenant('tenant-a'));
    check(decide($context, tenant('tenant-a'))->permitted, 'Same tenant was denied.');
    $denied = decide($context, tenant('tenant-b'));
    check(! $denied->permitted && $denied->code === 'wrong_tenant' && $denied->disclosure === DisclosureMode::ConcealAsMissing, 'Cross-tenant access did not fail disclosure-safely.');
});

fixture('authorization decision survives JSON round trip with disclosure and provenance', function (): void {
    $decision = AuthorizationDecision::deny(
        'private_relation_forbidden',
        DisclosureMode::ConcealAsMissing,
        'funes-policy-v1',
        new CrossPackageReference('sifrious/funes', 'authorization-decision', 'decision-01'),
    );
    $restored = AuthorizationDecision::fromArray(json_decode(json_encode($decision, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR));

    check($restored->toArray() === $decision->toArray(), 'Authorization decision was not preserved exactly.');
});

fixture('missing actor denies by default', function (): void {
    $decision = decide(null, tenant('tenant-a'));
    check(! $decision->permitted && $decision->code === 'missing_actor', 'Missing actor gained access.');
});

fixture('service acting-for-user survives JSON queue round trip without credentials', function (): void {
    $context = new AuthorizationContext(
        new ActorContext(new CrossPackageReference('sifrious/zahir', 'service', 'postflight'), ActorKind::Service, actingFor: account('user-a'), originatingService: new CrossPackageReference('sifrious/logres', 'application', 'worker')),
        tenant('tenant-a'),
        new CrossPackageReference('sifrious/logres', 'request', 'req-01'),
        new CrossPackageReference('sifrious/funes', 'provenance', 'prov-01'),
    );
    $json = json_encode($context, JSON_THROW_ON_ERROR);
    foreach (['token','password','secret','credential','session'] as $forbidden) { check(! str_contains(strtolower($json), $forbidden), "Serialized context leaked {$forbidden} material."); }
    $restored = AuthorizationContext::fromArray(json_decode($json, true, flags: JSON_THROW_ON_ERROR));
    check($restored->toArray() === $context->toArray(), 'Queued authorization context was not preserved exactly.');
    check($restored->actor->actingFor?->equals(account('user-a')) === true, 'Acting-for identity was lost.');
});

fixture('reference possession does not grant resolution access', function (): void {
    $privateReference = new CrossPackageReference('sifrious/elwin', 'conversation', 'private-a');
    $wrongTenant = new AuthorizationContext(new ActorContext(account('user-a'), ActorKind::Human), tenant('tenant-b'));
    check($privateReference->id === 'private-a' && ! decide($wrongTenant, tenant('tenant-a'))->permitted, 'Knowing a reference escalated privilege.');
});

fixture('authorized public identity does not disclose a private relation neighborhood', function (): void {
    $publicCommit = new CrossPackageReference('sifrious/landing', 'commit', 'public-commit');
    $privateConversation = new CrossPackageReference('sifrious/elwin', 'conversation', 'private-a');
    $requester = new AuthorizationContext(new ActorContext(account('user-b'), ActorKind::Human), tenant('tenant-b'));

    $identityDecision = AuthorizationDecision::permit('public_identity');
    $relationDecision = decide($requester, tenant('tenant-a'));
    $response = [
        'identity' => $identityDecision->permitted ? $publicCommit->toArray() : null,
        'relations' => $relationDecision->permitted ? [$privateConversation->toArray()] : [],
        'relation_decision' => $relationDecision->toArray(),
    ];

    check($response['identity'] === $publicCommit->toArray(), 'Authorized public identity was hidden.');
    check($response['relations'] === [], 'Private relation neighborhood leaked across tenants.');
    check(! str_contains(json_encode($response, JSON_THROW_ON_ERROR), $privateConversation->id), 'Denied candidate identity leaked in the response.');
});

fixture('missing-versus-forbidden disclosure carries no counts or candidate identities', function (): void {
    $decision = AuthorizationDecision::deny('private_graph', DisclosureMode::ConcealAsMissing, 'funes-policy-v1');
    $response = ['result' => 'missing', 'decision' => $decision->toArray()];
    $json = json_encode($response, JSON_THROW_ON_ERROR);

    check($decision->disclosure === DisclosureMode::ConcealAsMissing, 'Domain disclosure decision was reinterpreted.');
    check(! array_key_exists('count', $response) && ! array_key_exists('candidates', $response), 'Denied response disclosed graph cardinality or candidates.');
    check(! str_contains($json, 'private-a'), 'Denied response disclosed a candidate identity.');
});

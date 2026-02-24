<?php

class WP_SPID_CIE_OIDC_Spid_Registry_Service {
    const LIST_TRANSIENT = 'spid_saml_registry_idp_list_v2';
    const LIST_LKG_TRANSIENT = 'spid_saml_registry_idp_list_lkg_v2';
    const DETAIL_PREFIX = 'spid_saml_registry_idp_detail_v2_';
    const DETAIL_LKG_PREFIX = 'spid_saml_registry_idp_detail_lkg_v2_';
    const STATUS_TRANSIENT = 'spid_saml_registry_status_v2';
    const REGISTRY_JSON_LIST = 'https://registry.spid.gov.it/entities-idp?custom=info_display_base&output=json';
    const REGISTRY_JSON_LIST_FALLBACK = 'https://registry.spid.gov.it/entities-idp?output=json';
    const REGISTRY_XML_LIST = 'https://registry.spid.gov.it/entities?entity_type=idp';

    public function get_idp_list(bool $force = false) {
        if (!$force) {
            $cached = get_transient(self::LIST_TRANSIENT);
            if (is_array($cached) && !empty($cached)) {
                return $cached;
            }
        }

        $rows = [];
        $source = 'json';

        $fetched = $this->fetch_json_https(self::REGISTRY_JSON_LIST);
        if (!is_wp_error($fetched)) {
            $rows = $this->extract_list_rows_from_json($fetched);
        }

        if (empty($rows)) {
            $fetchedFallback = $this->fetch_json_https(self::REGISTRY_JSON_LIST_FALLBACK);
            if (!is_wp_error($fetchedFallback)) {
                $rows = $this->extract_list_rows_from_json($fetchedFallback);
                $source = 'json-fallback';
            }
        }

        if (empty($rows)) {
            $source = 'xml';
            $rows = $this->fetch_xml_fallback_list(self::REGISTRY_XML_LIST);
        }

        if (is_wp_error($rows)) {
            $lkg = get_transient(self::LIST_LKG_TRANSIENT);
            if (is_array($lkg) && !empty($lkg)) {
                $this->set_status('lkg', count($lkg));
                return $lkg;
            }
            return $rows;
        }

        $normalized = [];
        foreach ($rows as $item) {
            $n = $this->normalize_list_item(is_array($item) ? $item : []);
            if ($n['entity_id'] !== '') {
                $normalized[$n['entity_id']] = $n;
            }
        }

        if (empty($normalized)) {
            return new WP_Error('spid_registry_empty', __('Registry SPID vuoto.', 'wp-spid-cie-oidc'));
        }

        $lkg = get_transient(self::LIST_LKG_TRANSIENT);
        if (is_array($lkg) && !empty($lkg)) {
            $lkgByEntity = [];
            foreach ($lkg as $cachedItem) {
                if (!is_array($cachedItem)) {
                    continue;
                }
                $eid = (string) ($cachedItem['entity_id'] ?? '');
                if ($eid !== '') {
                    $lkgByEntity[$eid] = $cachedItem;
                }
            }
            foreach ($normalized as $eid => $item) {
                if (!empty($item['logo'])) {
                    continue;
                }
                if (!empty($lkgByEntity[$eid]['logo'])) {
                    $normalized[$eid]['logo'] = (string) $lkgByEntity[$eid]['logo'];
                }
            }
        }

        uasort($normalized, function (array $a, array $b) {
            return strcasecmp($a['name'], $b['name']);
        });

        $normalized = array_values($normalized);
        set_transient(self::LIST_TRANSIENT, $normalized, DAY_IN_SECONDS);
        set_transient(self::LIST_LKG_TRANSIENT, $normalized, WEEK_IN_SECONDS);
        $this->set_status($source, count($normalized));
        return $normalized;
    }

    public function get_idp_detail(string $entityId, string $registryLink = '', bool $force = false) {
        $entityId = trim($entityId);
        if ($entityId === '') {
            return new WP_Error('spid_registry_missing_entity', __('IdP non selezionato.', 'wp-spid-cie-oidc'));
        }

        $cacheKey = self::DETAIL_PREFIX . md5($entityId);
        $cacheLkgKey = self::DETAIL_LKG_PREFIX . md5($entityId);

        if (!$force) {
            $cached = get_transient($cacheKey);
            if (is_array($cached) && !empty($cached)) {
                return $cached;
            }
        }

        $parsed = [];
        $url = $this->build_detail_url($entityId, $registryLink);
        $detail = $this->fetch_json_https($url);
        if (!is_wp_error($detail)) {
            $parsed = $this->extract_runtime_values($detail);
        }

        if (empty($parsed['entity_id']) || empty($parsed['sso_url']) || empty($parsed['x509_cert'])) {
            $xmlFallback = $this->fetch_xml_fallback_detail($entityId);
            if (!is_wp_error($xmlFallback)) {
                $parsed = $this->merge_runtime_values($parsed, $xmlFallback);
            }
        }

        if (empty($parsed['entity_id']) || empty($parsed['sso_url']) || empty($parsed['x509_cert'])) {
            $lkg = get_transient($cacheLkgKey);
            if (is_array($lkg) && !empty($lkg)) {
                return $lkg;
            }
            return new WP_Error('spid_registry_detail_incomplete', __('Dettaglio IdP incompleto.', 'wp-spid-cie-oidc'));
        }

        set_transient($cacheKey, $parsed, DAY_IN_SECONDS);
        set_transient($cacheLkgKey, $parsed, WEEK_IN_SECONDS);
        return $parsed;
    }

    public function refresh_all(): void {
        delete_transient(self::LIST_TRANSIENT);
        $this->get_idp_list(true);
    }

    public function get_status(): array {
        $status = get_transient(self::STATUS_TRANSIENT);
        if (!is_array($status)) {
            return [
                'count' => 0,
                'source' => 'n/a',
                'fetched_at' => 0,
            ];
        }
        return [
            'count' => (int) ($status['count'] ?? 0),
            'source' => (string) ($status['source'] ?? 'n/a'),
            'fetched_at' => (int) ($status['fetched_at'] ?? 0),
        ];
    }

    private function set_status(string $source, int $count): void {
        set_transient(self::STATUS_TRANSIENT, [
            'count' => max(0, $count),
            'source' => $source,
            'fetched_at' => time(),
        ], WEEK_IN_SECONDS);
    }

    private function build_detail_url(string $entityId, string $registryLink): string {
        $url = '';
        if ($registryLink !== '' && stripos($registryLink, 'https://') === 0) {
            $url = $registryLink;
            if (strpos($url, 'output=') === false) {
                $url = add_query_arg('output', 'json', $url);
            }
        }
        if ($url === '') {
            $url = 'https://registry.spid.gov.it/entities-idp/' . rawurlencode($entityId) . '?output=json';
        }
        return $url;
    }

    private function fetch_json_https(string $url) {
        $url = esc_url_raw($url);
        if ($url === '' || stripos($url, 'https://') !== 0) {
            return new WP_Error('spid_registry_invalid_url', __('URL Registry non valido.', 'wp-spid-cie-oidc'));
        }

        $resp = wp_remote_get($url, ['timeout' => 10, 'redirection' => 3, 'limit_response_size' => 1024 * 1024]);
        if (is_wp_error($resp)) {
            return $resp;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code < 200 || $code > 299) {
            return new WP_Error('spid_registry_http_error', __('Registry SPID non disponibile.', 'wp-spid-cie-oidc'));
        }
        $data = json_decode((string) wp_remote_retrieve_body($resp), true);
        if (!is_array($data)) {
            return new WP_Error('spid_registry_json_error', __('Risposta Registry non valida.', 'wp-spid-cie-oidc'));
        }
        return $data;
    }

    private function extract_list_rows_from_json(array $payload): array {
        $rows = [];
        $candidates = [];
        if (isset($payload['items']) && is_array($payload['items'])) {
            $candidates[] = $payload['items'];
        }
        if (isset($payload['entities']) && is_array($payload['entities'])) {
            $candidates[] = $payload['entities'];
        }
        if (isset($payload[0]) && is_array($payload[0])) {
            $candidates[] = $payload;
        }

        foreach ($candidates as $candidate) {
            foreach ($candidate as $row) {
                if (is_array($row)) {
                    $rows[] = $row;
                }
            }
        }

        // Alcuni payload del Registry arrivano come mappa associativa:
        // {"<entityID>": { ... info_display_base ... }}
        // In quel caso preserviamo la chiave come entity_id.
        if (empty($rows)) {
            foreach ($payload as $k => $v) {
                if (!is_array($v)) {
                    continue;
                }
                $key = is_string($k) ? trim($k) : '';
                if ($key === '') {
                    continue;
                }

                $entity = '';
                if (preg_match('#^https?://#i', $key)) {
                    $entity = $key;
                }

                if ($entity === '') {
                    $entity = (string) ($v['entity_id'] ?? $v['entityID'] ?? '');
                }

                if ($entity === '') {
                    continue;
                }

                $row = $v;
                $row['entity_id'] = $entity;
                $rows[] = $row;
            }
        }

        if (empty($rows)) {
            array_walk_recursive($payload, function ($value, $key) use (&$rows) {
                if (($key === 'entity_id' || $key === 'entityID') && is_string($value) && trim($value) !== '') {
                    $rows[] = ['entity_id' => trim($value)];
                }
            });
        }

        return $rows;
    }

    private function fetch_xml_fallback_list(string $url) {
        $xml = $this->fetch_xml_https($url);
        if (is_wp_error($xml)) {
            return $xml;
        }

        $xp = new DOMXPath($xml);
        $xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $rows = [];
        foreach ($xp->query('//md:EntityDescriptor') as $entityNode) {
            if (!$entityNode instanceof DOMElement) {
                continue;
            }
            $entityId = trim((string) $entityNode->getAttribute('entityID'));
            if ($entityId === '') {
                continue;
            }
            $name = trim((string) $xp->evaluate('string(md:Organization/md:OrganizationDisplayName)', $entityNode));
            if ($name === '') {
                $name = trim((string) $xp->evaluate('string(md:Organization/md:OrganizationName)', $entityNode));
            }
            $rows[] = [
                'entity_id' => $entityId,
                'organization_name' => $name,
            ];
        }

        if (empty($rows)) {
            return new WP_Error('spid_registry_empty', __('Registry SPID vuoto.', 'wp-spid-cie-oidc'));
        }

        return $rows;
    }

    private function fetch_xml_fallback_detail(string $entityId) {
        $xml = $this->fetch_xml_https(self::REGISTRY_XML_LIST);
        if (is_wp_error($xml)) {
            return $xml;
        }

        $xp = new DOMXPath($xml);
        $xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $query = sprintf('//md:EntityDescriptor[@entityID=%s]', $this->xpath_literal($entityId));
        $entityNode = $xp->query($query)->item(0);
        if (!$entityNode instanceof DOMElement) {
            return new WP_Error('spid_registry_entity_not_found', __('IdP non trovato nel Registry.', 'wp-spid-cie-oidc'));
        }

        $sso = '';
        foreach ($xp->query('.//md:SingleSignOnService', $entityNode) as $svcNode) {
            if (!$svcNode instanceof DOMElement) {
                continue;
            }
            $location = trim((string) $svcNode->getAttribute('Location'));
            $responseLocation = trim((string) $svcNode->getAttribute('ResponseLocation'));
            $binding = strtolower(trim((string) $svcNode->getAttribute('Binding')));
            if ($location === '' && $responseLocation === '') {
                continue;
            }
            if ($sso === '') {
                $sso = $location !== '' ? $location : $responseLocation;
            }
            if (strpos($binding, 'http-redirect') !== false) {
                $sso = $location !== '' ? $location : $responseLocation;
                break;
            }
        }

        $slo = '';
        foreach ($xp->query('.//md:SingleLogoutService', $entityNode) as $svcNode) {
            if (!$svcNode instanceof DOMElement) {
                continue;
            }
            $location = trim((string) $svcNode->getAttribute('Location'));
            $responseLocation = trim((string) $svcNode->getAttribute('ResponseLocation'));
            if ($location !== '' || $responseLocation !== '') {
                $slo = $location !== '' ? $location : $responseLocation;
                break;
            }
        }

        $certs = [];
        foreach ($xp->query('.//md:IDPSSODescriptor/md:KeyDescriptor//ds:X509Certificate', $entityNode) as $certNode) {
            $cert = trim((string) $certNode->textContent);
            if ($cert !== '') {
                $certs[] = preg_replace('/\s+/', '', $cert);
            }
        }

        return [
            'entity_id' => $entityId,
            'sso_url' => esc_url_raw($sso),
            'slo_url' => esc_url_raw($slo),
            'x509_cert' => implode("\n", array_unique($certs)),
        ];
    }

    private function fetch_xml_https(string $url) {
        $url = esc_url_raw($url);
        if ($url === '' || stripos($url, 'https://') !== 0) {
            return new WP_Error('spid_registry_invalid_url', __('URL Registry non valido.', 'wp-spid-cie-oidc'));
        }

        $resp = wp_remote_get($url, ['timeout' => 12, 'redirection' => 3, 'limit_response_size' => 1024 * 1024]);
        if (is_wp_error($resp)) {
            return $resp;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code < 200 || $code > 299) {
            return new WP_Error('spid_registry_http_error', __('Registry SPID non disponibile.', 'wp-spid-cie-oidc'));
        }

        $xml = new DOMDocument();
        $ok = @$xml->loadXML((string) wp_remote_retrieve_body($resp), LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOERROR | LIBXML_NOWARNING);
        if (!$ok) {
            return new WP_Error('spid_registry_xml_invalid', __('Risposta Registry non valida.', 'wp-spid-cie-oidc'));
        }

        return $xml;
    }

    private function normalize_list_item(array $item): array {
        $entity = (string) ($item['entity_id'] ?? $item['entityID'] ?? '');
        $name = (string) ($item['organization_name'] ?? $item['display_name'] ?? $item['name'] ?? $entity);
        $link = (string) ($item['registry_link'] ?? $item['registryLink'] ?? '');
        $logo = (string) ($item['logo'] ?? $item['logo_url'] ?? $item['icon'] ?? $item['image'] ?? '');

        if (isset($item['info_display_base']) && is_array($item['info_display_base'])) {
            $ib = $item['info_display_base'];
            if ($name === '' || $name === $entity) {
                $name = (string) ($ib['organization_name'] ?? $ib['display_name'] ?? $ib['name'] ?? $name);
            }
            if ($logo === '') {
                $logo = (string) ($ib['logo'] ?? $ib['logo_url'] ?? $ib['icon'] ?? $ib['image'] ?? '');
            }
        }

        if (isset($item['metadata']) && is_array($item['metadata'])) {
            $m = $item['metadata'];
            if ($entity === '') {
                $entity = (string) ($m['entity_id'] ?? $m['entityID'] ?? '');
            }
            if ($name === '') {
                $name = (string) ($m['organization_name'] ?? $m['name'] ?? '');
            }
            if ($link === '') {
                $link = (string) ($m['registry_link'] ?? $m['registryLink'] ?? '');
            }
            if ($logo === '') {
                $logo = (string) ($m['logo'] ?? $m['logo_url'] ?? $m['icon'] ?? $m['image'] ?? '');
            }
            if ($logo === '' && isset($m['info_display_base']) && is_array($m['info_display_base'])) {
                $ib = $m['info_display_base'];
                $logo = (string) ($ib['logo'] ?? $ib['logo_url'] ?? $ib['icon'] ?? $ib['image'] ?? '');
            }
        }

        $normalized = [
            'entity_id' => trim($entity),
            'name' => trim($name !== '' ? $name : $entity),
            'registry_link' => esc_url_raw(trim($link)),
            'logo' => $this->normalize_logo_url((string) $logo),
        ];

        if (!empty($item['logo_uri'])) {
            $normalized['logo'] = esc_url_raw((string) $item['logo_uri']);
        }

        if (!empty($item['info_display_base']) && is_array($item['info_display_base']) && !empty($item['info_display_base']['logo_uri'])) {
            $normalized['logo'] = esc_url_raw((string) $item['info_display_base']['logo_uri']);
        }

        return $normalized;
    }


    private function normalize_logo_url(string $logo): string {
        $logo = trim($logo);
        if ($logo === '') {
            return '';
        }

        if (strpos($logo, '//') === 0) {
            $logo = 'https:' . $logo;
        } elseif (strpos($logo, '/') === 0) {
            $logo = 'https://registry.spid.gov.it' . $logo;
        } elseif (!preg_match('#^https?://#i', $logo)) {
            $logo = 'https://registry.spid.gov.it/' . ltrim($logo, '/');
        }

        return esc_url_raw($logo);
    }

    private function extract_runtime_values(array $detail): array {
        $entity = (string) ($detail['entity_id'] ?? $detail['entityID'] ?? '');
        $sso = '';
        $slo = '';
        $certs = [];

        $visit = function ($node) use (&$visit, &$entity, &$sso, &$slo, &$certs): void {
            if (!is_array($node)) {
                return;
            }
            if ($entity === '') {
                $entity = (string) ($node['entity_id'] ?? $node['entityID'] ?? $node['issuer'] ?? '');
            }
            if ($sso === '') {
                $sso = $this->extract_url_value($node['sso_url'] ?? '');
                if ($sso === '') {
                    $sso = $this->extract_url_value($node['single_sign_on_service'] ?? '');
                }
            }
            if ($slo === '') {
                $slo = $this->extract_url_value($node['slo_url'] ?? '');
                if ($slo === '') {
                    $slo = $this->extract_url_value($node['single_logout_service'] ?? '');
                }
            }
            $cert = (string) ($node['signing_certificate_x509'] ?? $node['x509_certificate'] ?? '');
            if ($cert !== '') {
                $certs[] = trim($cert);
            }

            foreach (['single_sign_on_service', 'single_sign_on_services', 'sso', 'sso_services'] as $k) {
                if (!empty($node[$k]) && is_array($node[$k])) {
                    foreach ($node[$k] as $svc) {
                        if (!is_array($svc)) {
                            continue;
                        }
                        $loc = (string) ($svc['location'] ?? $svc['url'] ?? $svc['response_location'] ?? '');
                        $binding = strtolower((string) ($svc['binding'] ?? ''));
                        if ($loc !== '' && $sso === '') {
                            $sso = $loc;
                        }
                        if ($loc !== '' && str_contains($binding, 'redirect')) {
                            $sso = $loc;
                            break;
                        }
                    }
                }
            }
            foreach (['single_logout_service', 'single_logout_services', 'slo', 'slo_services'] as $k) {
                if (!empty($node[$k]) && is_array($node[$k])) {
                    foreach ($node[$k] as $svc) {
                        if (!is_array($svc)) {
                            continue;
                        }
                        $loc = (string) ($svc['location'] ?? $svc['url'] ?? $svc['response_location'] ?? '');
                        if ($loc !== '') {
                            $slo = $loc;
                            break;
                        }
                    }
                }
            }
            foreach (['signing_certificate_x509', 'signing_certificates_x509', 'x509_certificates'] as $k) {
                if (!empty($node[$k])) {
                    if (is_array($node[$k])) {
                        foreach ($node[$k] as $c) {
                            if (is_string($c) && trim($c) !== '') {
                                $certs[] = trim($c);
                            }
                        }
                    } elseif (is_string($node[$k]) && trim($node[$k]) !== '') {
                        $certs[] = trim($node[$k]);
                    }
                }
            }
            foreach ($node as $child) {
                if (is_array($child)) {
                    $visit($child);
                }
            }
        };

        $visit($detail);

        return [
            'entity_id' => trim($entity),
            'sso_url' => esc_url_raw(trim($sso)),
            'slo_url' => esc_url_raw(trim($slo)),
            'x509_cert' => implode("\n", array_values(array_unique(array_filter($certs)))),
        ];
    }

    private function extract_url_value($value): string {
        if (is_string($value)) {
            return trim($value);
        }

        if (is_array($value)) {
            if (isset($value['location']) && is_string($value['location'])) {
                return trim($value['location']);
            }
            if (isset($value['url']) && is_string($value['url'])) {
                return trim($value['url']);
            }
            if (isset($value['response_location']) && is_string($value['response_location'])) {
                return trim($value['response_location']);
            }
            foreach ($value as $item) {
                $candidate = $this->extract_url_value($item);
                if ($candidate !== '') {
                    return $candidate;
                }
            }
        }

        return '';
    }


    private function merge_runtime_values(array $primary, array $fallback): array {
        return [
            'entity_id' => !empty($primary['entity_id']) ? (string) $primary['entity_id'] : (string) ($fallback['entity_id'] ?? ''),
            'sso_url' => !empty($primary['sso_url']) ? (string) $primary['sso_url'] : (string) ($fallback['sso_url'] ?? ''),
            'slo_url' => !empty($primary['slo_url']) ? (string) $primary['slo_url'] : (string) ($fallback['slo_url'] ?? ''),
            'x509_cert' => !empty($primary['x509_cert']) ? (string) $primary['x509_cert'] : (string) ($fallback['x509_cert'] ?? ''),
        ];
    }

    private function xpath_literal(string $value): string {
        if (strpos($value, "'") === false) {
            return "'" . $value . "'";
        }
        if (strpos($value, '"') === false) {
            return '"' . $value . '"';
        }

        $parts = explode("'", $value);
        $safe = array_map(function ($part) {
            return "'" . $part . "'";
        }, $parts);
        return 'concat(' . implode(',"\'",', $safe) . ')';
    }
}

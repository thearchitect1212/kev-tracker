-- Questions a vulnerability-management team would ask of the KEV catalog.
-- Each query is named with a "-- name:" line so report.py can run it by name.

-- name: totals
SELECT COUNT(*)                                   AS total_cves,
       SUM(ransomware)                            AS ransomware_cves,
       ROUND(100.0 * SUM(ransomware) / COUNT(*), 1) AS ransomware_pct,
       MIN(date_added)                            AS first_added,
       MAX(date_added)                            AS last_added
FROM vulnerabilities;

-- name: top_vendors
SELECT vendor,
       COUNT(*)        AS cves,
       SUM(ransomware) AS ransomware_cves
FROM vulnerabilities
GROUP BY vendor
ORDER BY cves DESC
LIMIT 10;

-- name: added_per_year
SELECT SUBSTR(date_added, 1, 4) AS year_added,
       COUNT(*)                 AS cves,
       SUM(ransomware)          AS ransomware_cves
FROM vulnerabilities
GROUP BY year_added
ORDER BY year_added;

-- name: top_weaknesses
SELECT w.cwe,
       COUNT(*)          AS cves,
       SUM(v.ransomware) AS ransomware_cves
FROM weaknesses w
JOIN vulnerabilities v ON v.cve_id = w.cve_id
GROUP BY w.cwe
ORDER BY cves DESC
LIMIT 10;

-- name: old_flaws_still_exploited
-- How old was each flaw when it was added to the list?
SELECT CASE
         WHEN CAST(SUBSTR(date_added, 1, 4) AS INTEGER) - cve_year = 0 THEN '0 (same year)'
         WHEN CAST(SUBSTR(date_added, 1, 4) AS INTEGER) - cve_year = 1 THEN '1 year'
         WHEN CAST(SUBSTR(date_added, 1, 4) AS INTEGER) - cve_year BETWEEN 2 AND 4 THEN '2-4 years'
         ELSE '5+ years'
       END      AS age_when_added,
       COUNT(*) AS cves
FROM vulnerabilities
GROUP BY age_when_added
ORDER BY age_when_added;

-- name: added_last_30_days
SELECT cve_id, vendor, product, date_added, due_date, ransomware
FROM vulnerabilities
WHERE date_added >= DATE((SELECT MAX(date_added) FROM vulnerabilities), '-30 days')
ORDER BY date_added DESC, cve_id;

-- name: vendor_rank_by_year
-- Window function: each vendor's rank within the year its CVEs were added.
SELECT year_added, vendor, cves, vendor_rank
FROM (
    SELECT SUBSTR(date_added, 1, 4) AS year_added,
           vendor,
           COUNT(*) AS cves,
           RANK() OVER (PARTITION BY SUBSTR(date_added, 1, 4)
                        ORDER BY COUNT(*) DESC) AS vendor_rank
    FROM vulnerabilities
    GROUP BY year_added, vendor
)
WHERE vendor_rank <= 3
ORDER BY year_added, vendor_rank;

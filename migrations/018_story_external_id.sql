-- Adds the external ID and link to stories and fills them from metadata.wordpress_id.
-- Set @wordpress_url first, see README.md. Of stories sharing a post, the newest gets the ID.
SET @url_check = IF(@wordpress_url LIKE 'http%://%' AND @wordpress_url NOT LIKE '%/', 'DO 0',
    'DO `Set @wordpress_url, see migrations/README.md`');
PREPARE url_check FROM @url_check;
ALTER TABLE stories
    ADD COLUMN external_id VARBINARY(100) NULL AFTER metadata,
    ADD COLUMN external_url VARBINARY(500) NULL AFTER external_id,
    ADD UNIQUE KEY idx_stories_external_id (external_id);
UPDATE stories s
JOIN (SELECT MAX(id) AS id, JSON_VALUE(metadata, '$.wordpress_id') AS wordpress_id FROM stories
      GROUP BY wordpress_id HAVING wordpress_id IS NOT NULL) newest ON newest.id = s.id
SET s.external_id = newest.wordpress_id,
    s.external_url = CONCAT(@wordpress_url, '/wp-admin/post.php?post=', newest.wordpress_id, '&action=edit'),
    s.updated_at = s.updated_at;  -- the column has ON UPDATE, and clients sort on it

-- Adds the external ID and link to stories and fills them from metadata.wordpress_id.
-- Set @wordpress_url first, see README.md. Of stories without an ID that share a post, the one with the highest id gets it, unless a story already has it.
SET @url_check = IF(COALESCE(@wordpress_url, '') REGEXP '^https?://.*[^/]$', 'DO 0',
    'DO `Set @wordpress_url, see migrations/README.md`');
PREPARE url_check FROM @url_check;  -- A bad value fails here on the unknown column, so no EXECUTE.
ALTER TABLE stories
    ADD COLUMN external_id VARBINARY(100) NULL AFTER metadata,
    ADD COLUMN external_url VARBINARY(500) NULL AFTER external_id,
    ADD UNIQUE KEY idx_stories_external_id (external_id);
UPDATE stories s
JOIN (SELECT MAX(id) AS id, CAST(JSON_VALUE(metadata, '$.wordpress_id') AS BINARY) AS wordpress_id FROM stories
      WHERE external_id IS NULL GROUP BY wordpress_id HAVING wordpress_id IS NOT NULL) newest ON newest.id = s.id
LEFT JOIN stories holder ON holder.external_id = newest.wordpress_id
SET s.external_id = newest.wordpress_id,
    s.external_url = CONCAT(@wordpress_url, '/wp-admin/post.php?post=', newest.wordpress_id, '&action=edit'),
    s.updated_at = s.updated_at WHERE holder.id IS NULL;  -- the column has ON UPDATE, and clients sort on it
